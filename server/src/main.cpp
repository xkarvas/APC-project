// server/main.cpp
#define ASIO_STANDALONE
#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>
#include <vector>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sodium.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <atomic>


#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif


#include <filesystem>
namespace fs = std::filesystem;

using asio::ip::tcp;

static std::string endpoint_str(const tcp::socket& sock) {
    asio::error_code ec;
    auto ep = sock.remote_endpoint(ec);
    if (ec) {
        return "";
    }
    std::ostringstream oss;
    oss << ep;
    return oss.str();
}

static bool set_socket_recv_timeout(tcp::socket& sock, int seconds)
{
#if defined(_WIN32)
    DWORD timeout = (seconds > 0) ? seconds * 1000 : 0;
    if (setsockopt(sock.native_handle(),
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout),
                   sizeof(timeout)) != 0) {
        return false;
    }
    return true;
#else
    struct timeval tv;
    tv.tv_sec  = seconds;
    tv.tv_usec = 0; 
    if (setsockopt(sock.native_handle(),
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &tv,
                   sizeof(tv)) != 0) {
        return false;
    }
    return true;
#endif
}

static std::vector<unsigned char> hex_to_vec(const std::string& hex) {
    std::vector<unsigned char> out(hex.size() / 2);
    size_t outlen = 0;
    if (sodium_hex2bin(out.data(), out.size(),
                       hex.c_str(), hex.size(),
                       nullptr, &outlen, nullptr) != 0) {
        throw std::runtime_error("invalid hex");
    }
    out.resize(outlen);
    return out;
}

static bool ct_equal_hex(const std::string& a_hex, const std::string& b_hex) {
    auto a = hex_to_vec(a_hex);
    auto b = hex_to_vec(b_hex);
    if (a.size() != b.size()) return false;
    int rc = sodium_memcmp(a.data(), b.data(), a.size());
    sodium_memzero(a.data(), a.size());
    sodium_memzero(b.data(), b.size());
    return rc == 0;
}

std::string prepare_user_root(const std::string& root, const std::string& user) {
    fs::path base_root = root;
    fs::path users_dir = base_root / ".users";
    fs::path user_dir  = users_dir / user;

    std::error_code ec;

    // vytvor root (ak ešte neexistuje)
    fs::create_directories(base_root, ec);

    // vytvor ./root/users
    ec.clear();
    fs::create_directories(users_dir, ec);

    // vytvor ./root/users/<user>
    ec.clear();
    fs::create_directories(user_dir, ec);

    // vráť kanonickú (alebo aspoň normálnu) cestu ako string
    std::error_code ec2;
    fs::path canon = fs::weakly_canonical(user_dir, ec2);
    if (ec2) {
        // ak zlyhá canonicalizácia, vráť aspoň "raw" cestu
        return user_dir.string();
    }
    return canon.string();
}

inline std::string iso_now_utc() {
    using namespace std::chrono;
    auto t = system_clock::to_time_t(system_clock::now());
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%FT%TZ");
    return oss.str();
}

static inline void write_u32_be(uint32_t v, unsigned char out[4]) {
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >> 8)  & 0xFF;
    out[3] = v & 0xFF;
}
static inline uint32_t read_u32_be(const unsigned char in[4]) {
    return (uint32_t(in[0]) << 24) | (uint32_t(in[1]) << 16) | (uint32_t(in[2]) << 8) | uint32_t(in[3]);
}

static std::string trimQuotes(std::string s) {
    auto q = [](char c){ return c=='\'' || c=='"'; };
    if (!s.empty() && q(s.front())) s.erase(s.begin());
    if (!s.empty() && q(s.back()))  s.pop_back(); // zvládne aj ./data'
    return s;
}



static bool recv_json(tcp::socket& s, nlohmann::json& out) {
    unsigned char hdr[4];
    asio::error_code ec;
    size_t n = asio::read(s, asio::buffer(hdr, 4), ec);
    if (ec || n != 4) return false;
    uint32_t len = read_u32_be(hdr);
    std::string payload(len, '\0');
    asio::read(s, asio::buffer(payload.data(), len), ec);
    if (ec) return false;
    // std::cout << "[server] <- " << payload << "\n";
    out = nlohmann::json::parse(payload);
    return true;
}
static void send_json(tcp::socket& s, const nlohmann::json& j) {
    const std::string payload = j.dump();
    unsigned char hdr[4];
    write_u32_be(static_cast<uint32_t>(payload.size()), hdr);
    asio::write(s, asio::buffer(hdr, 4));
    asio::write(s, asio::buffer(payload.data(), payload.size()));
    // std::cout << "[server] -> " << payload << "\n";
}

bool is_path_under_root(const std::string& root, const std::string& path) {
    try {
        fs::path rootPath   = fs::weakly_canonical(root);
        fs::path targetPath = fs::weakly_canonical(path);

        // pomocná funkcia: či prefixPath je prefixom fullPath (na úrovni path komponentov)
        auto isPrefix = [](const fs::path& prefixPath, const fs::path& fullPath) {
            auto pit = prefixPath.begin();
            auto fit = fullPath.begin();
            for (; pit != prefixPath.end() && fit != fullPath.end(); ++pit, ++fit) {
                if (*pit != *fit)
                    return false;
            }
            return std::distance(prefixPath.begin(), prefixPath.end()) <=
                   std::distance(fullPath.begin(), fullPath.end());
        };

        // 1) základná podmienka: path musí byť pod rootom (alebo rovná rootu)
        if (!isPrefix(rootPath, targetPath)) {
            return false;
        }

        // 2) zisti, či root už je niekde v .users (private mód)
        bool rootInsideUsers = false;
        for (auto it = rootPath.begin(); it != rootPath.end(); ++it) {
            if (it->filename() == ".users") {
                rootInsideUsers = true;
                break;
            }
        }

        // 3) ak root NIE JE v .users (public mód), zakáž prístup do root/.users/**
        if (!rootInsideUsers) {
            fs::path usersRoot = rootPath / ".users";
            if (isPrefix(usersRoot, targetPath)) {
                // pokus ísť do .users alebo niečoho pod ním -> zakáž
                return false;
            }
        }

        // všetko OK
        return true;
    }
    catch (...) {
        return false; // ak sa niečo pokazí (napr. neexistuje cesta)
    }
}

static uintmax_t directory_size(const fs::path& dir) {
    uintmax_t total = 0;
    try {
        if (fs::exists(dir) && fs::is_directory(dir)) {
            for (auto const& entry : fs::recursive_directory_iterator(dir)) {
                if (entry.is_regular_file()) {
                    total += entry.file_size();
                }
            }
        }
    } catch (...) {
        // ak zlyhá prístup k niektorému súboru, len preskočíme
    }
    return total;
}

std::string hash_file(const fs::path& path)
{
    const size_t HASH_LEN = 32;
    unsigned char hash[HASH_LEN];

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, nullptr, 0, HASH_LEN) != 0) {
        throw std::runtime_error("crypto_generichash_init failed");
    }

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        throw std::runtime_error("Cannot open file for hashing: " + path.string());
    }

    char buf[4096];
    while (true) {
        f.read(buf, sizeof(buf));
        std::streamsize n = f.gcount();
        if (n <= 0) break;
        if (crypto_generichash_update(&state,
                                      reinterpret_cast<unsigned char*>(buf),
                                      static_cast<unsigned long long>(n)) != 0) {
            throw std::runtime_error("crypto_generichash_update failed");
        }
    }

    if (crypto_generichash_final(&state, hash, HASH_LEN) != 0) {
        throw std::runtime_error("crypto_generichash_final failed");
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < HASH_LEN; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

void build_dir_index(const fs::path& root_dir,
                     const fs::path& current,
                     nlohmann::json& entries)
{
    for (const auto& entry : fs::directory_iterator(current)) {
        fs::path rel = fs::relative(entry.path(), root_dir);
        std::string rel_str = rel.generic_string();

        if (entry.is_directory()) {
            entries.push_back({
                {"rel", rel_str},
                {"type", "dir"}
            });

            // rekurzia dovnútra
            build_dir_index(root_dir, entry.path(), entries);
        } else if (entry.is_regular_file()) {
            std::uintmax_t size = 0;
            std::error_code ec;
            size = fs::file_size(entry.path(), ec);

            std::string h = hash_file(entry.path());

            entries.push_back({
                {"rel", rel_str},
                {"type", "file"},
                {"size", size},
                {"hash", h}
            });
        }
    }
}

void write_part_info(const std::string& root,
                     const std::string& cmd,
                     int64_t chunk_index,
                     int64_t total_chunks,
                     const std::string& local_path,
                     const std::string& remote_path)
{
    try {
        fs::path part_path = fs::path(root) / ".part";   // napr. /user/root/.part

        nlohmann::json j = {
            {"cmd",          cmd},
            {"chunk_index",  chunk_index},
            {"total_chunks", total_chunks},
            {"local",        local_path},
            {"remote",       remote_path}
        };

        std::ofstream f(part_path, std::ios::app);  // append
        if (!f.is_open()) {
            std::cerr << "[error] cannot open part file: "
                      << part_path << "\n";
            return;
        }

        f << j.dump() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[error] write_part_info failed: " << e.what() << "\n";
    }
}

static void handle_client(tcp::socket sock, const fs::path& root) {
    try {
        // authentication phase
        nlohmann::json auth;
        if (!recv_json(sock, auth)) {
            std::cerr << "[error] " << endpoint_str(sock) << " auth failed\n";
            return;
        }
        if (auth.value("cmd", "") != "AUTH") {
            std::cerr << "[error] " << endpoint_str(sock) << " auth failed: invalid command\n";
            return;
        } else {
            std::string username = auth.value("username", "");


            if (username.empty()) {
                send_json(sock, {{"cmd","AUTH"},{"status","OK"},{"code",0},{"message","Authentication successful"},{"data","Welcome guest"},{"root",root.string()},{"mode","public"}});
                std::cout << "[info] " << endpoint_str(sock) << " connect in public mode\n";
            } else {
                std::error_code ec;
                fs::create_directories("./server/users", ec);
                if (ec) {
                    std::cerr << "[error] create_directories error: " << ec.message() << "\n";
                    send_json(sock, {{"cmd","AUTH"},{"status","ERROR"},{"code",1}});
                }

                fs::path p = fs::absolute("./server/users/users.json");

                if (!fs::exists(p) || (fs::exists(p) && fs::file_size(p) == 0)) {
                    std::ofstream init(p, std::ios::trunc);
                    init << R"({"users":{}})";
                    init.close();
                }

                using json = nlohmann::json;


                json db;
                {
                    std::ifstream in(p);
                    try {
                        in >> db;
                    } catch (...) {
                        db = json{{"users", json::object()}};
                        std::ofstream fix(p, std::ios::trunc);
                        fix << db.dump(2);
                    }
                }
                if (!db.contains("users") || !db["users"].is_object()) {
                    db["users"] = json::object();
                }


                if (db["users"].contains(username)) {
                    //std::cout << "[auth] User '" << username << "' exists\n";
                    send_json(sock, {{"cmd","AUTH"},{"status","OK"},{"code",0},{"next","LOGIN"},{"salt",db["users"][username]["salt"]}});

                    if (!recv_json(sock, auth)) {
                        std::cerr << "[error] " << endpoint_str(sock) << " auth failed\n";
                        return;
                    }
                    if (auth.value("cmd", "") != "LOGIN") {
                        std::cerr << "[error] " << endpoint_str(sock) << " auth failed\n";
                        return;
                    }


                    auto& userrec = db["users"][username];

                    std::string submitted_hex = auth.value("password", "");            // to, čo poslal klient (HEX)
                    std::string stored_hex    = userrec.value("password_hash", "");    // to, čo máš v DB (HEX)


                    if (!submitted_hex.empty() && !stored_hex.empty()
                            && ct_equal_hex(submitted_hex, stored_hex)) {
                        userrec["last_login_at"] = iso_now_utc();

                        {
                            std::ofstream out(p, std::ios::trunc);
                            out << db.dump(2);
                        }

                        fs::path base_root = root; 
                        std::string user_root_str = prepare_user_root(base_root.string(), username);

                        




                        bool has_part = false;
                        nlohmann::json part_entries = nlohmann::json::array();

                        try {
                            fs::path part_path = fs::path(user_root_str) / ".part";

                            if (fs::exists(part_path) && fs::is_regular_file(part_path)) {
                                has_part = true;

                                std::ifstream pf(part_path);
                                if (!pf.is_open()) {
                                    std::cerr << "[error] cannot open .part file for user "
                                            << username << ": " << part_path << "\n";
                                } else {
                                    std::string line;
                                    while (std::getline(pf, line)) {
                                        if (line.empty()) continue;

                                        try {
                                            nlohmann::json j = nlohmann::json::parse(line);
                                            part_entries.push_back(j);
                                        } catch (const std::exception& e) {
                                            std::cerr << "[warn] failed to parse line in .part for user "
                                                    << username << ": " << e.what() << "\n";
                                        }
                                    }
                                }
                            }
                            fs::remove(part_path);
                        } catch (const std::exception& e) {
                            std::cerr << "[error] while reading .part for user "
                                    << username << ": " << e.what() << "\n";
                        }

                        std::cout << "[auth] User " << username << " was successfully logged in!\n";

                        // priprav LOGIN odpoveď
                        nlohmann::json login_resp = {
                            {"cmd","LOGIN"},
                            {"status","OK"},
                            {"code",0},
                            {"message","Welcome!"},
                            {"root", user_root_str},
                            {"has_part", has_part}
                        };

                        if (has_part) {
                            // tu pošleme zoznam všetkých „rozrobených“ operácií
                            login_resp["part"] = part_entries;
                        }

                        send_json(sock, login_resp);;
                    } else {
                        send_json(sock, {
                            {"cmd","LOGIN"},{"status","ERROR"},{"code",1},
                            {"message","Bad credentials"}
                        });
                        std::cerr << "[error] " << endpoint_str(sock)
                                << " auth failed - Bad credentials.\n";
                    }
                } else {

                    unsigned char salt_raw[crypto_pwhash_SALTBYTES];
                    randombytes_buf(salt_raw, sizeof salt_raw);
                    char salt_b64[64]; 
                    sodium_bin2base64(salt_b64, sizeof salt_b64,
                                    salt_raw, sizeof salt_raw,
                                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
                    std::string salt_b64_str = salt_b64;



                    //std::cout << "[auth] User '" << username << "' NOT found... register\n";
                    send_json(sock, {{"cmd","AUTH"},{"status","OK"},{"code",0},{"next","REGISTER"},{"salt",salt_b64_str}});

                    if (!recv_json(sock, auth)) {
                        std::cerr << "[error] " << endpoint_str(sock) << " auth failed\n";
                        return;
                    }

                    if (auth.value("cmd", "") != "REGISTER") {
                        std::cerr << "[error] " << endpoint_str(sock) << " auth failed\n";
                        return;
                    }

                    std::string password_hash = auth.value("password", "");   // alebo "verifier", ak to tak voláš
                    if (password_hash.empty()) {
                        send_json(sock, {{"cmd","REGISTER"},{"status","ERROR"},{"code",2},{"message","missing password hash"}});
                        return;
                    }

                    nlohmann::json userrec = {
                        {"user", username},
                        {"password_hash", password_hash}, // klient posiela HEX alebo Base64 – ulož presne to, čo príde
                        {"salt", salt_b64_str},           // tvoje Base64 URL-safe (bez '=')
                        {"registered_at", iso_now_utc()},
                        {"last_login_at", iso_now_utc()}
                    };

                    db["users"][username] = std::move(userrec);


                    {
                        std::ofstream out(p, std::ios::trunc);
                        out << db.dump(2);
                    }

                    std::cout << "[auth] User " << username << " was succesfully registered!\n";

                    fs::path base_root = root; 
                    std::string user_root_str = prepare_user_root(base_root.string(), username);


                    send_json(sock, {{"cmd","REGISTER"},{"status","OK"},{"code",0},{"message","Registered"},{"root",user_root_str}});
                }
            }
        }

        while (true) {
            nlohmann::json req;
            if (!recv_json(sock, req)) break;

            const std::string cmd = req.value("cmd", "");
            const auto args = req.value("args", nlohmann::json::object());
            const auto root = req.value("root", "");
            const auto client_port = req.value("client_port", "");
            // std::cout << "[server] cmd=" << cmd << " args=" << args.dump() << "\n";

            if (cmd == "LIST") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","LIST"},{"status","ERROR"},{"code",2},{"message", "Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " list -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                std::string result;
                try {
                    nlohmann::json files = nlohmann::json::array();

                    for (const auto& entry : fs::directory_iterator(path)) {
                        nlohmann::json item;
                        item["name"] = entry.path().filename().string();

                        if (entry.is_directory()) {
                            item["type"] = "directory";
                            uintmax_t size = directory_size(entry.path());
                            item["size"] = std::to_string(size);
                        } else if (entry.is_regular_file()) {
                            item["type"] = "file";
                            item["size"] = std::to_string(entry.file_size());
                        } else if (entry.is_symlink()) {
                            item["type"] = "symlink";
                            item["size"] = "-";
                        } else {
                            item["type"] = "other";
                            item["size"] = "-";
                        }

                        files.push_back(item);
                    }

                    send_json(sock, {{"cmd","LIST"},{"status","OK"},{"code",0},{"message","LIST command executed"},{"data", files.dump()}});
                    std::cout << "[ok] " << endpoint_str(sock) << " list -> " << "path: " << path <<"\n";

                } catch (const std::exception& e) {
                    result = std::string("Error: ") + e.what();
                    send_json(sock, {{"cmd","LIST"},{"status","ERROR"},{"code",1},{"message","LIST command failed"},{"data", result}});
                    std::cout << "[error] " << endpoint_str(sock) << " list ->" << result << std::endl;
                }               // TODO: implement LIST command
            } else if (cmd == "CD") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " cd -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(path)) {
                        if (std::filesystem::is_directory(path)) {
                            // Je to priečinok
                            send_json(sock, {{"cmd","CD"},{"status","OK"},{"code",0},{"path", path}});
                            std::cout << "[ok] " << endpoint_str(sock) << " cd -> ok, changed to '" << path << "'" << "\n";

                        } else {
                            send_json(sock, {{"cmd","CD"},{"status","WARNING"},{"code",-1},{"path", path},{"message","Not a directory"}});
                            std::cout << "[error] " << endpoint_str(sock) << " cd -> not a directory, path: '" << path << "'\n";
                        }
                    } else {
                        // neexistuje
                        send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",1},{"path", path},{"message","Directory does not exist"}});
                        std::cout << "[error] " << endpoint_str(sock) << " cd -> directory does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",1},{"path", path},{"message","Unknown error"}});
                    std::cout << "[error] " << endpoint_str(sock) << " cd -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "MKDIR") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " mkdir -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(path)) {
                        send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",1},{"message","Directory already exists"}});
                        std::cout << "[error] " << endpoint_str(sock) << " mkdir -> directory already exists, path: '" << path << "'\n";
                    } else {
                        std::filesystem::create_directories(path);
                        send_json(sock, {{"cmd","MKDIR"},{"status","OK"},{"code",0},{"message","Directory created"}});
                        std::cout << "[ok] " << endpoint_str(sock) << " mkdir -> created directory at '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",1},{"message","Failed to create directory"}});
                    std::cout << "[error] " << endpoint_str(sock) << " mkdir -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "RMDIR") {
                std::string path = args.value("path", "");
                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " rmdir -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }
                try {
                    if (std::filesystem::exists(path)) {
                        if (!std::filesystem::is_directory(path)) {
                            send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Path is not a directory"}});
                            std::cout << "[error] " << endpoint_str(sock) << " rmdir -> path is not a directory, path: '" << path << "'\n";
                            continue;
                        }
                        std::filesystem::remove_all(path);
                        send_json(sock, {{"cmd","RMDIR"},{"status","OK"},{"code",0},{"message","Directory removed"}});
                        std::cout << "[ok] " << endpoint_str(sock) << " rmdir -> removed directory at '" << path << "'\n";
                    } else {
                        send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Directory does not exist"}});
                        std::cout << "[error] " << endpoint_str(sock) << " rmdir -> directory does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Failed to remove directory"}});
                    std::cout << "[error] " << endpoint_str(sock) << " rmdir -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "DELETE") {
                std::string path = args.value("path", "");
                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " delete -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }
                try {
                    if (std::filesystem::exists(path)) {
                        if (std::filesystem::is_directory(path)) {
                            send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","Path is directory not a file"}});
                            std::cout << "[error] " << endpoint_str(sock) << " delete -> path is not a file, path: '" << path << "'\n";
                            continue;
                        }
                        std::filesystem::remove(path);
                        send_json(sock, {{"cmd","DELETE"},{"status","OK"},{"code",0},{"message","File deleted"}});
                        std::cout << "[ok] " << endpoint_str(sock) << " delete -> removed file at '" << path << "'\n";
                    } else {
                        send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","File does not exist"}});
                        std::cout << "[error] " << endpoint_str(sock) << " delete -> file does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","Failed to delete file"}});
                    std::cout << "[error] " << endpoint_str(sock) << " delete -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "MOVE") {
                std::string src = args.value("src", "");
                std::string dst = args.value("dst", "");

                if (!is_path_under_root(root, src) || !is_path_under_root(root, dst)) {
                    send_json(sock, {{"cmd","MOVE"},{"status","ERROR"},{"code",2},{"message","Access denied: source or destination path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " move -> access denied, src: " << src << ", dst: " << dst << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(src)) {
                        std::filesystem::rename(src, dst);
                        send_json(sock, {{"cmd","MOVE"},{"status","OK"},{"code",0},{"message","Move/Rename successful"}});
                        std::cout << "[ok] " << endpoint_str(sock) << " move -> moved/renamed from '" << src << "' to '" << dst << "'\n";
                    } else {
                        send_json(sock, {{"cmd","MOVE"},{"status","ERROR"},{"code",1},{"message","Source path does not exist"}});
                        std::cout << "[error] " << endpoint_str(sock) << " move -> source path does not exist, src: '" << src << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","MOVE"},{"status","ERROR"},{"code",1},{"message","Failed to move/rename"}});
                    std::cout << "[error] " << endpoint_str(sock) << " move -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "COPY") {
                std::string src = args.value("src", "");
                std::string dst = args.value("dst", "");

                if (!is_path_under_root(root, src) || !is_path_under_root(root, dst)) {
                    send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",2},{"message","Access denied: source or destination path is outside root (" + root + ")"}});
                    std::cout << "[error] " << endpoint_str(sock) << " copy -> access denied, src: " << src << ", dst: " << dst << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (!fs::exists(src)) {
                        send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",1},{"message","Source does not exist"},{"data", ""}});
                        std::cout << "[error] " << endpoint_str(sock) << " copy -> source does not exist: '" << src << "'\n";
                        continue;
                    }

                    // 🔒 ochrana proti kopírovaniu do svojho podpriečinka
                    fs::path srcPath = fs::weakly_canonical(src);
                    fs::path dstPath = fs::weakly_canonical(dst);

                    if (dstPath.string().find(srcPath.string()) == 0) {
                        send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",3},
                                        {"message","Destination is inside source directory (would cause infinite recursion)"},{"data", ""}});
                        std::cout << "[error] " << endpoint_str(sock) << " copy -> destination is inside source directory\n";
                        continue;
                    }
                    if (std::filesystem::exists(src)) {
                        if (std::filesystem::is_directory(src)) {
                            std::filesystem::copy(src, dst, fs::copy_options::recursive);
                        } else {
                            std::filesystem::copy_file(src, dst);
                        }
                        send_json(sock, {{"cmd","COPY"},{"status","OK"},{"code",0},{"message","Copy successful"}});
                        std::cout << "[ok] " << endpoint_str(sock) << " copy -> copied from '" << src << "' to '" << dst << "'\n";
                    } else {
                        send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",1},{"message","Source path does not exist"}});
                        std::cout << "[error] " << endpoint_str(sock) << " copy -> source path does not exist, src: '" << src << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",1},{"message","Failed to copy"}});
                    std::cout << "[error] " << endpoint_str(sock) << " copy -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "DOWNLOAD") {
                std::string path = args.value("remote", "");

                if (!std::filesystem::exists(path) || !std::filesystem::is_regular_file(path)) {
                    send_json(sock, {{"cmd", "DOWNLOAD"}, {"status", "ERROR"}, {"message", "File not found"}});
                    std::cout << "[error] " << endpoint_str(sock) << " download -> file not found: " << path << "\n";
                    continue;
                }

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {
                        {"cmd",    "DOWNLOAD"},
                        {"status", "ERROR"},
                        {"code",   2},
                        {"message","Access denied: path is outside root (" + root + ")"}
                    });
                    std::cout << "[error] " << endpoint_str(sock)
                            << " download -> access denied, path: " << path
                            << ", root: " << root << "\n";
                    continue;
                }

                const size_t CHUNK_SIZE = 64 * 1024; // 64 KB
                std::ifstream file(path, std::ios::binary);
                if (!file.is_open()) {
                    send_json(sock, {{"cmd", "DOWNLOAD"}, {"status", "ERROR"}, {"message", "Cannot open file"}});
                    std::cout << "[error] " << endpoint_str(sock) << " download -> cannot open file: " << path << "\n";
                    continue;
                }

                int64_t file_size    = std::filesystem::file_size(path);
                int64_t total_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

                std::cout << "[server] Starting download file '" << path
                        << "' of size " << file_size << " bytes in "
                        << total_chunks << " chunks. From client: "
                        << endpoint_str(sock) << "\n";

                send_json(sock, {
                    {"cmd", "DOWNLOAD"},
                    {"status", "OK"},
                    {"size", file_size},
                    {"chunk_size", CHUNK_SIZE},
                    {"total_chunks", total_chunks}
                });

                std::vector<char> buffer(CHUNK_SIZE);
                int64_t sent_total = 0;
                bool download_error = false;
                bool resume_mode = false;

                int64_t start_chunk = 0;
                if (args.contains("resume_from_chunk")) {
                    int64_t resume_chunk = args.value("resume_from_chunk", 0);

                    if (resume_chunk < 0) resume_chunk = 0;
                    if (resume_chunk > total_chunks) resume_chunk = total_chunks;

                    if (resume_chunk > 0 && resume_chunk < total_chunks) {
                        start_chunk = resume_chunk;
                        resume_mode = true;

                        sent_total = resume_chunk * CHUNK_SIZE;
                        std::cout << "[info] Resuming download from chunk " << resume_chunk
                                << " for client " << endpoint_str(sock) << "\n";
                    }
                }
                
                for (int64_t i = start_chunk; i < total_chunks && !download_error;) {
                    int64_t offset        = i * CHUNK_SIZE;
                    int64_t bytes_to_send = std::min<int64_t>(CHUNK_SIZE, file_size - offset);

                    file.seekg(offset, std::ios::beg);
                    file.read(buffer.data(), bytes_to_send);
                    std::streamsize bytes_read = file.gcount();
                    if (bytes_read <= 0) {
                        std::cout << "\n[error] download -> failed to read chunk " << i << " from file\n";
                        download_error = true;
                        break;
                    }

                    nlohmann::json header = {
                        {"chunk_index", i},
                        {"size", static_cast<int64_t>(bytes_read)}
                    };

                    int retry = 0;
                    while (true) {
                        // pošli header + dáta
                        send_json(sock, header);
                        asio::write(sock, asio::buffer(buffer.data(), bytes_read));

                        // if(!set_socket_recv_timeout(sock, 30)) {
                        //     std::cout << "\n[error] download -> failed to set socket recv timeout\n";
                        //     download_error = true;
                        //     break;
                        // }
                        nlohmann::json ack;
                        bool got = recv_json(sock, ack);
                        //set_socket_recv_timeout(sock, 0);

                        if (!got) {
                            std::cout << "\n[error] " << endpoint_str(sock)
                                    << " timeout or disconnect while waiting for ACK of chunk "
                                    << i << "\n";
                            download_error = true;
                            break;
                        }

                        std::string st = ack.value("status", "");
                        int64_t ack_i  = ack.value("ack", -1);
                        int64_t nack_i = ack.value("nack", -1);

                        if (st == "OK" && ack_i == i) {
                            // OK – chunk potvrdený
                            sent_total += bytes_read;

                            double progress = (file_size > 0)
                                ? (100.0 * (double)sent_total / (double)file_size)
                                : 0.0;

                            std::cout << "\r[info] sent chunk " << (i + 1) << "/"
                                    << total_chunks << " ("
                                    << std::fixed << std::setprecision(1)
                                    << progress << "%) to client "
                                    << endpoint_str(sock) << std::flush;

                            ++i; // ďalší chunk
                            break;
                        }
                        else if (st == "ERROR" && nack_i == i) {
                            // klient NACK – zopakuj chunk
                            std::cout << "\n[error] client " << endpoint_str(sock)
                                    << " NACK for chunk " << i
                                    << " – resending...\n";

                            if (++retry >= 3) {
                                std::cout << "[error] chunk " << i
                                        << " NACKed too many times, aborting download\n";
                                download_error = true;
                                break;
                            }
                            // while(true) pokračuje – pošle znovu ten istý buffer
                        }
                        else if (st == "ERROR" && ack.value("message", "") == "Download interrupted") {
                            std::cout << "\n[error] client " << endpoint_str(sock)
                                    << " aborted the download.\n";

                            if (ack.value("private_mode", false)) {
                                std::cout << "[info] download interrupted in private mode, saving progress info.\n";
                                write_part_info(root, "DOWNLOAD", i, total_chunks, path, ack.value("remote_path", ""));
                            }
                            download_error = true;
                            break;
                        }
                        else {
                            std::cout << "\n[error] invalid ACK/NACK for chunk " << i
                                    << " from client " << endpoint_str(sock)
                                    << " (status=" << st << ", ack=" << ack_i
                                    << ", nack=" << nack_i << ")\n";
                            download_error = true;
                            break;
                        }
                    }
                }

                file.close();
                if (!download_error) {

                    std::cout << "\n[ok] download finished successfully for " << path
                            << " to client " << endpoint_str(sock) << "\n";
                } else {
                    std::cout << "[error] download aborted for " << path
                            << " to client " << endpoint_str(sock) << "\n";
                }
            } else if (cmd == "UPLOAD") {

                std::string path     = args.value("remote", "");
                std::string filename = fs::path(args.value("local", "")).filename().string();
                std::string path_with_filename = (fs::path(path) / filename).string();

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","UPLOAD"},{"status","ERROR"},{"code",2},
                                    {"message","Access denied: path is outside root (" + root + ")"}, 
                                    {"data","Access denied: path is outside root (" + root + ")"}} );
                    std::cout << "[error] " << endpoint_str(sock)
                            << " upload -> access denied, path: " << path
                            << ", root: " << root
                            << " local_path: " << args.value("local", "") << "\n";
                    continue;
                }

                if (!fs::is_directory(path)) {
                    send_json(sock, {{"cmd","UPLOAD"},{"status","ERROR"},{"message","Remote path is not directory"}});
                    std::cout << "[error] " << endpoint_str(sock)
                            << " upload -> remote path is not directory: " << path << "\n";
                    continue;
                }

                if (fs::exists(path_with_filename)) {
                    send_json(sock, {{"cmd","UPLOAD"},{"status","ERROR"},{"message","File already exists"}});
                    std::cout << "[error] " << endpoint_str(sock)
                            << " upload -> file already exists at '" << path_with_filename << "'\n";
                    continue;
                }

                send_json(sock, {{"cmd", "UPLOAD"}, {"status", "OK"}, {"message", "Ready to receive chunks"}});

                nlohmann::json meta;
                if (!recv_json(sock, meta)) {
                    std::cout << "[error] " << endpoint_str(sock)
                            << " upload -> failed to receive meta\n";
                    continue;
                }

                int64_t total_size    = meta.value("size", 0);
                int64_t meta_chunk_sz = meta.value("chunk_size", 0);
                int64_t total_chunks  = meta.value("total_chunks", 0);

                std::ofstream outfile(path_with_filename, std::ios::binary);
                if (!outfile.is_open()) {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "ERROR"}, {"message", "Cannot create file"}});
                    std::cout << "[error] " << endpoint_str(sock)
                            << " upload -> cannot create file at '" << path_with_filename << "'\n";
                    continue;
                }

                send_json(sock, {{"cmd", "UPLOAD"}, {"status", "OK"}, {"message", "Start sending chunks"}});
                std::cout << "[server] Starting upload file '" << path_with_filename
                        << "' of size " << total_size << " bytes in "
                        << total_chunks << " chunks. From client: "
                        << endpoint_str(sock) << "\n";

                bool upload_error = false;

                for (int64_t i = 0; i < total_chunks && !upload_error; /* i++ až po ACK */) {

                    nlohmann::json chunk_header;
                    if (!recv_json(sock, chunk_header)) {
                        std::cout << "\n[error] " << endpoint_str(sock)
                                << " client disconnected during upload.\n";
                        upload_error = true;
                        break;
                    }

                    int64_t chunk_index = chunk_header.value("chunk_index", -1);
                    int64_t chunk_size  = chunk_header.value("size", 0);

                    if (chunk_index != i || chunk_size <= 0) {
                        std::cout << "\n[error] " << endpoint_str(sock)
                                << " invalid chunk header for chunk " << i
                                << " — NACK\n";
                        send_json(sock, {{"status", "ERROR"}, {"nack", i}});
                        continue;
                    }

                    std::vector<char> buffer(chunk_size);
                    asio::error_code ec;
                    size_t bytes_read = asio::read(sock, asio::buffer(buffer.data(), chunk_size), ec);


                    if (ec || bytes_read != static_cast<size_t>(chunk_size)) {
                        std::cout << "\n[error] " << endpoint_str(sock)
                                << " NACK for chunk " << i
                                << " (read error)" << "\n";
                        send_json(sock, {{"status", "ERROR"}, {"nack", i}});
                        continue;                 
                    }

                    outfile.write(buffer.data(), chunk_size);

                    send_json(sock, {{"status", "OK"}, {"ack", i}});

                    double progress = 100.0 * double(i + 1) / double(total_chunks);
                    std::cout << "\r[info] upload chunk " << (i + 1) << "/"
                            << total_chunks << " ("
                            << std::fixed << std::setprecision(1)
                            << progress << "%) from client: "
                            << endpoint_str(sock) << std::flush;

                    ++i;
                }

                outfile.close();

                if (!upload_error) {
                    std::cout << "\n[ok] upload finished successfully for '"
                            << path_with_filename << "' from client "
                            << endpoint_str(sock) << "\n";
                } else {
                    std::cout << "[error] upload failed for '"
                            << path_with_filename << "' from client "
                            << endpoint_str(sock) << "\n";
                    std::error_code ec;
                    fs::remove(path_with_filename, ec);
                }

            } else if (cmd == "SYNC") {
                std::string path = args.value("remote", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {
                        {"cmd", "SYNC"},
                        {"status", "ERROR"},
                        {"code", 1},
                        {"message", "Access denied: path is outside root"}
                    });
                    std::cout << "[error] " << endpoint_str(sock)
                              << " sync -> access denied, path: '" << path
                              << "', root: '" << root << "'\n";
                    continue;
                }

                fs::path p(path);
                if (!fs::exists(p) || !fs::is_directory(p)) {
                    send_json(sock, {
                        {"cmd", "SYNC"},
                        {"status", "ERROR"},
                        {"code", 2},
                        {"message", "Path is not existing directory on server"}
                    });
                    std::cout << "[error] " << endpoint_str(sock)
                              << " sync -> path not dir: '" << path << "'\n";
                    continue;
                }

                try {
                    nlohmann::json entries = nlohmann::json::array();
                    build_dir_index(p, p, entries);

                    send_json(sock, {
                        {"cmd", "SYNC"},
                        {"status", "OK"},
                        {"code", 0},
                        {"path", path},
                        {"entries", entries}
                    });

                    std::cout << "[ok] " << endpoint_str(sock)
                              << " sync -> index for '" << path
                              << "' sent, entries=" << entries.size() << "\n\n\n";
                }
                catch (const std::exception& e) {
                    send_json(sock, {
                        {"cmd", "SYNC"},
                        {"status", "ERROR"},
                        {"code", 3},
                        {"message", std::string("Failed to build index: ") + e.what()}
                    });
                    std::cout << "[error] " << endpoint_str(sock)
                              << " sync -> exception: " << e.what() << "\n";

                } 
            } else {
                send_json(sock, {{"cmd", cmd}, {"status","ERROR"}, {"code",1}, {"message","Unknown command"}});
                std::cout << "[error] " << endpoint_str(sock) << " unknown command: " << cmd << "\n";
            }
        } 
    } catch (const std::exception& e) {
        std::cout << "[server] exception: " << e.what() << "\n";
    }
    std::cout << "[server] client " << endpoint_str(sock) << " disconnected\n";
}


static std::atomic_bool g_terminate{false};

void handle_signal(int)
{
    g_terminate.store(true, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
    int port = 5050;
    fs::path root = ".";

    if (sodium_init() < 0) {
        std::cerr << "[server] sodium_init failed\n";
        return 1;
    }

    for (int i = 1; i < argc; ) {
        std::string arg = argv[i];

        if (arg.rfind("--", 0) != 0) {
            std::cerr << "Unexpected positional argument: " << arg << "\n";
            return 2;
        }

        std::string key, val;
        if (auto eq = arg.find('='); eq != std::string::npos) {
            key = arg.substr(2, eq - 2);
            val = arg.substr(eq + 1);
            ++i; // spotrebovali sme iba jeden argv
        } else {
            key = arg.substr(2);
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --" << key << "\n";
                return 2;
            }
            val = argv[i + 1];
            i += 2; // preskoč aj hodnotu
        }

        val = trimQuotes(val);

        if (key == "port") {
            try {
                int p = std::stoi(val);
                if (p < 1 || p > 65535) throw std::out_of_range("port");
                port = p;
            } catch (...) {
                std::cerr << "Invalid --port: " << val << " (expected 1..65535)\n";
                return 2;
            }
        } else if (key == "root") {
            if (val.empty()) {
                std::cerr << "Invalid --root: empty path\n";
                return 2;
            }
            root = val; // string/path, nie stoi!
        } else {
            std::cerr << "Unknown option: --" << key << "\n";
            return 2;
        }
    }

    try {
        if (!fs::exists(root)) fs::create_directories(root);
        root = fs::weakly_canonical(root);
    } catch (const std::exception& e) {
        std::cerr << "Failed to prepare root directory: " << e.what() << "\n";
        return 2;
    }

    // std::signal(SIGINT,  handle_signal);   
    // std::signal(SIGTERM, handle_signal);   
    // std::signal(SIGQUIT, handle_signal); 

    // 4) Spustenie servera
    std::cout << "[server] starting...\n";


    std::cout << "[server] listening on 0.0.0.0:" << port
              << ", root: " << root.string() << "\n";

    try {
        asio::io_context io;
        tcp::acceptor acc(io, tcp::endpoint(tcp::v4(), (unsigned short)port)); // 0.0.0.0:<port>

        while (!g_terminate.load(std::memory_order_relaxed)) {
            tcp::socket sock(io);
            asio::error_code ec;
            acc.accept(sock, ec); // môže byť prerušený signálom

            if (g_terminate.load(std::memory_order_relaxed)) {
                break;
            }

            if (ec) {
                std::cerr << "[server] accept error: " << ec.message() << "\n";
                continue;
            }

            std::thread(handle_client, std::move(sock), root).detach();
        }

        asio::error_code ignore;
        acc.close(ignore);
        std::cout << "[server] shutting down (signal)\n";
    } catch (const std::exception& e) {
        std::cerr << "[server] fatal: " << e.what() << "\n";
        return 1;
    }
}