#define ASIO_STANDALONE
#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <fstream>
#include <regex>
#include <sodium.h>
#include <sstream>




#include <filesystem>
namespace fs = std::filesystem;

using asio::ip::tcp;

// --- big-endian helpers ---
static inline void write_u32_be(uint32_t v, unsigned char out[4]) {
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >> 8)  & 0xFF;
    out[3] = v & 0xFF;
}
static inline uint32_t read_u32_be(const unsigned char in[4]) {
    return (uint32_t(in[0]) << 24) | (uint32_t(in[1]) << 16) | (uint32_t(in[2]) << 8) | uint32_t(in[3]);
}

// --- blocking I/O ---
static void send_json(tcp::socket& s, const nlohmann::json& j) {
    const std::string payload = j.dump();
    unsigned char hdr[4];
    write_u32_be(static_cast<uint32_t>(payload.size()), hdr);
    asio::write(s, asio::buffer(hdr, 4));
    asio::write(s, asio::buffer(payload.data(), payload.size()));
    // std::cout << "[client] -> " << payload << "\n";
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
    // std::cout << "[client] <- " << payload << "\n";
    out = nlohmann::json::parse(payload);
    return true;
}

// --- pomocné: rozdelenie slov, trim, basename ---
static void split_words(const std::string& line, std::vector<std::string>& out) {
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok) out.push_back(tok);
}
static std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::toupper(c); });
    return s;
}
static std::string basename_of(const std::string& p) {
    auto pos = p.find_last_of("/\\");
    return (pos == std::string::npos) ? p : p.substr(pos+1);
}


template <size_t N>
std::array<unsigned char, N> b64url_to_array(const std::string& b64) {
    std::array<unsigned char, N> out{};
    size_t outlen = 0;
    if (sodium_base642bin(out.data(), out.size(),
                          b64.c_str(), b64.size(),
                          nullptr, &outlen, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
        || outlen != N) {
        throw std::runtime_error("invalid b64 salt or wrong length");
    }
    return out;
}
// hashing with salt
static std::string argon2id_hex(const std::string& password,
                                const unsigned char salt[crypto_pwhash_SALTBYTES]) {
    unsigned char out[32];
    if (crypto_pwhash(out, sizeof out,
                      password.c_str(), password.size(),
                      salt,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Argon2id failed");
    }
    char hex[sizeof(out) * 2 + 1];
    sodium_bin2hex(hex, sizeof hex, out, sizeof out);
    sodium_memzero(out, sizeof out);
    return std::string(hex);
}

static std::string argon2id_hex_b64salt(const std::string& password,
                                        const std::string& salt_b64) {
    auto salt = b64url_to_array<crypto_pwhash_SALTBYTES>(salt_b64);
    return argon2id_hex(password, salt.data());
}



static void print_help_all() {
    using std::cout;
    using std::left;
    using std::setw;

    // jednoduchá hlavička (bez farieb, aby to fungovalo všade)
    cout << "\n"
         << "╔══════════════════════════════════════════════╗\n"
         << "║              MiniDrive – HELP                ║\n"
         << "╚══════════════════════════════════════════════╝\n\n";

    cout << "  Commands (<> required, [] optional):\n\n";

    struct Row {
        const char* cmd;
        const char* args;
        const char* desc;
    };

    Row rows[] = {
        {"LIST",     "[path]",                      "List directory contents (default: current remote dir)"},
        {"UPLOAD",   "<local_path> <remote_dir>",   "Upload local file into remote directory"},
        {"DOWNLOAD", "<remote_path> <local_dir>",   "Download remote file into local directory"},
        {"DELETE",   "<path>",                      "Delete a remote file"},
        {"CD",       "<path>",                      "Change remote working directory"},
        {"MKDIR",    "<path>",                      "Create a remote directory (recursively)"},
        {"RMDIR",    "<path>",                      "Remove a remote directory (recursively)"},
        {"MOVE",     "<src> <dst>",                 "Move / rename file or directory on server"},
        {"COPY",     "<src> <dst>",                 "Copy file or directory on server"},
        {"SYNC",     "<local> <remote>",            "One-way sync: make remote directory match local"},
        {"HELP",     "[command]",                   "Show this help or detailed help for a command"},
        {"EXIT",     "",                            "Exit client (also: QUIT, Q, E)"}
    };

    const int w_cmd  = 10;
    const int w_args = 24;

    cout << "  " << left << setw(w_cmd)  << "CMD"
         << " " << left << setw(w_args) << "ARGS"
         << "DESCRIPTION\n";

    cout << "  " << std::string(w_cmd + w_args + 35, '-') << "\n";

    for (const auto& r : rows) {
        cout << "  " << left << setw(w_cmd)  << r.cmd
             << " " << left << setw(w_args) << r.args
             << r.desc << "\n";
    }

    cout << "\n"
         << "  Examples:\n"
         << "    LIST\n"
         << "    UPLOAD /Users/ervinkarvas/reqs-tf.txt /docs\n"
         << "    DOWNLOAD /docs/report.pdf /Users/ervinkarvas\n"
         << "    SYNC /Users/ervinkarvas /backup/ervinkarvas\n\n";
}

static void print_help_cmd(const std::string& CMD) {
    using std::cout;

    if (CMD == "LIST") {
        cout <<
            "\nLIST [path]\n"
            "  List contents of a remote directory.\n"
            "  - If [path] is omitted, the current remote directory is used.\n"
            "  - Example: LIST\n"
            "             LIST /backup/photos\n\n";
    }
    else if (CMD == "UPLOAD") {
        cout <<
            "\nUPLOAD <local_path> <remote_dir>\n"
            "  Upload a local file into a remote directory.\n"
            "  - <local_path>  : path to an existing local file.\n"
            "  - <remote_dir>  : existing directory on the server.\n"
            "  The file keeps its original filename on the server.\n"
            "  - Example: UPLOAD report.pdf /docs\n\n";
    }
    else if (CMD == "DOWNLOAD") {
        cout <<
            "\nDOWNLOAD <remote_path> <local_dir>\n"
            "  Download a remote file into a local directory.\n"
            "  - <remote_path> : full path to a file on the server.\n"
            "  - <local_dir>   : existing local directory; the filename\n"
            "                    is taken from <remote_path>.\n"
            "  - Example: DOWNLOAD /docs/report.pdf /downloads\n\n";
    }
    else if (CMD == "DELETE") {
        cout <<
            "\nDELETE <path>\n"
            "  Delete a remote file.\n"
            "  - <path> must be an existing file on the server.\n"
            "  - Use RMDIR for directories.\n"
            "  - Example: DELETE /docs/report.pdf\n\n";
    }
    else if (CMD == "CD") {
        cout <<
            "\nCD <path>\n"
            "  Change the current remote working directory.\n"
            "  - Use absolute or relative paths.\n"
            "  - Special values:\n"
            "      .   -> stay in current directory\n"
            "      ..  -> go back to root of your repository\n"
            "  - Example: CD /backup\n\n";
    }
    else if (CMD == "MKDIR") {
        cout <<
            "\nMKDIR <path>\n"
            "  Create a remote directory (recursively if needed).\n"
            "  - Fails if the directory already exists.\n"
            "  - Example: MKDIR /backup/2025/week-11\n\n";
    }
    else if (CMD == "RMDIR") {
        cout <<
            "\nRMDIR <path>\n"
            "  Remove a remote directory and its contents recursively.\n"
            "  - Use with care: this permanently deletes everything inside.\n"
            "  - Example: RMDIR /backup/tmp\n\n";
    }
    else if (CMD == "MOVE") {
        cout <<
            "\nMOVE <src> <dst>\n"
            "  Move or rename a file or directory on the server.\n"
            "  - Works both as rename and as move between directories.\n"
            "  - Example: MOVE /docs/report.pdf /archive/report_old.pdf\n"
            "             MOVE /docs/report.pdf /docs/report_old.pdf\n\n";
    }
    else if (CMD == "COPY") {
        cout <<
            "\nCOPY <src> <dst>\n"
            "  Copy a file or directory on the server.\n"
            "  - Directories are copied recursively.\n"
            "  - Example: COPY /docs /backup/docs_copy\n\n";
    }
    else if (CMD == "SYNC") {
        cout <<
            "\nSYNC <local_dir> <remote_dir>\n"
            "  One-way synchronization: LOCAL → REMOTE.\n"
            "  - Both <local_dir> (on client) and <remote_dir> (on server)\n"
            "    must be existing directories.\n"
            "  - After SYNC, <remote_dir> will match <local_dir>:\n"
            "      * files/dirs missing on server are created,\n"
            "      * extra files/dirs on server are deleted,\n"
            "      * changed files (by hash) are re-uploaded.\n"
            "  - Operation is recursive.\n"
            "  - Example: SYNC /project /backup/project\n\n";
    }
    else if (CMD == "HELP") {
        cout <<
            "\nHELP [command]\n"
            "  Show general help or detailed help for a specific command.\n"
            "  - Example: HELP\n"
            "             HELP SYNC\n\n";
    }
    else if (CMD == "EXIT") {
        cout <<
            "\nEXIT\n"
            "  Exit the client.\n"
            "  - Aliases: QUIT, Q, E\n\n";
    }
    else {
        std::cout << "\nUnknown command. Type HELP for the list of commands.\n\n";
    }
}

static bool need_args(const std::string& CMD, size_t have, size_t& min_req, size_t& max_all, std::string& usage) {
    // usage text
    if (CMD == "LIST")       { usage = "LIST [path]";                         min_req=0; max_all=1; }
    else if (CMD == "UPLOAD"){ usage = "UPLOAD <local_path> <remote_path>";   min_req=2; max_all=2; }
    else if (CMD == "DOWNLOAD"){ usage= "DOWNLOAD <remote_path> <local_path>";min_req=2; max_all=2; }
    else if (CMD == "DELETE"){ usage = "DELETE <path>";                        min_req=1; max_all=1; }
    else if (CMD == "CD")    { usage = "CD <path>";                            min_req=1; max_all=1; }
    else if (CMD == "MKDIR") { usage = "MKDIR <path>";                         min_req=1; max_all=1; }
    else if (CMD == "RMDIR") { usage = "RMDIR <path>";                         min_req=1; max_all=1; }
    else if (CMD == "MOVE")  { usage = "MOVE <src> <dst>";                     min_req=2; max_all=2; }
    else if (CMD == "COPY")  { usage = "COPY <src> <dst>";                     min_req=2; max_all=2; }
    else if (CMD == "SYNC")  { usage = "SYNC <src> <dst>";                     min_req=2; max_all=2; }
    else if (CMD == "HELP")  { usage = "HELP [command]";                       min_req=0; max_all=1; }
    else if (CMD == "EXIT" || CMD=="QUIT") { usage = "EXIT";                   min_req=0; max_all=0; }
    else { usage = ""; min_req=0; max_all=0; return false; }

    if (have < min_req) {
        // vypíš, ktoré <...> chýbajú (iba stručne)
        std::cout << "\n[warning] missing required argument(s) for " << CMD << ". Usage: " << usage << "\n\n";
        return false;
    }
    if (have > max_all) {
        std::cout << "\n[warning] too many arguments for " << CMD << ". Usage: " << usage << "\n\n";
        return false;
    }
    return true;
}

bool is_path_under(const std::string& path1, const std::string& path2) {
    try {
        fs::path rootPath = fs::weakly_canonical(path1);
        fs::path targetPath = fs::weakly_canonical(path2);

        // over, či začiatok targetPath == rootPath
        auto rootIt = rootPath.begin();
        auto pathIt = targetPath.begin();

        for (; rootIt != rootPath.end() && pathIt != targetPath.end(); ++rootIt, ++pathIt) {
            if (*rootIt != *pathIt)
                return false;
        }

        // Ak sme prešli celý rootPath bez rozdielu, path je pod rootom alebo rovná
        return std::distance(rootPath.begin(), rootPath.end()) <= std::distance(targetPath.begin(), targetPath.end());
    }
    catch (...) {
        return false; // ak sa niečo pokazí (napr. neexistujúca cesta)
    }
}

std::string formatSize(const std::string& sizeStr) {
    double size = std::stod(sizeStr); // z JSONu alebo reťazca
    const char* units[] = {"B", "kB", "MB", "GB", "TB"};
    int unitIndex = 0;

    // škáluj jednotky, kým je hodnota >= 1000
    while (size >= 1000.0 && unitIndex < 4) {
        size /= 1024.0;
        unitIndex++;
    }

    // ak je príliš malé (napr. < 0.8 kB), posuň späť
    while (size < 0.8 && unitIndex > 0) {
        size *= 1024.0;
        unitIndex--;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
    return oss.str();
}

std::pair<std::string,std::string> splitUserIp(const std::string& s) {
    // nájdi IPv4 na KONCI reťazca
    static const std::regex ipAtEnd(R"(((?:\d{1,3}\.){3}\d{1,3})$)");
    std::smatch m;
    if (!std::regex_search(s, m, ipAtEnd)) return {"", ""}; // nenašlo IP

    std::string ip = m[1].str();
    std::string user = s.substr(0, m.position()); // všetko pred IP

    // voliteľne: over rozsah oktetov 0..255
    auto ok = [&]{
        int a,b,c,d;
        return std::sscanf(ip.c_str(), "%d.%d.%d.%d", &a,&b,&c,&d)==4
            && (0<=a&&a<=255)&&(0<=b&&b<=255)&&(0<=c&&c<=255)&&(0<=d&&d<=255);
    }();
    if (!ok) return {"",""};

    return {user, ip};
}

bool do_upload(tcp::socket& sock,
               const std::string& port,
               const std::string& root,
               const fs::path& local_full,
               const fs::path& remote_dir_for_file)
{
    // 1) prvý UPLOAD command – to isté, ako keď user napíše UPLOAD
    nlohmann::json args_up = {
        {"local",  local_full.generic_string()},
        {"remote", remote_dir_for_file.generic_string()}
    };
    nlohmann::json req_up = {
        {"client_port", port},
        {"cmd", "UPLOAD"},
        {"args", args_up},
        {"root", root}
    };
    send_json(sock, req_up);

    nlohmann::json resp_up;
    if (!recv_json(sock, resp_up)) {
        std::cout << "[upload] server closed connection\n";
        return false;
    }
    if (resp_up.value("status", "") != "OK") {
        std::cout << "[upload] server rejected upload to '"
                  << remote_dir_for_file << "': "
                  << resp_up.value("message", "") << "\n";
        return false;
    }

    const size_t CHUNK_SIZE = 64 * 1024;
    std::ifstream file(local_full, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[upload] cannot open local file " << local_full << "\n";
        return false;
    }

    int64_t file_size = fs::file_size(local_full);
    int64_t total_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

    std::cout << "[upload] starting file '" << local_full
              << "' (" << file_size << " bytes, "
              << total_chunks << " chunks)\n";

    nlohmann::json meta = {
        {"cmd", "UPLOAD"},
        {"status", "OK"},
        {"size", file_size},
        {"chunk_size", (int64_t)CHUNK_SIZE},
        {"total_chunks", total_chunks}
    };
    send_json(sock, meta);

    nlohmann::json resp_meta;
    if (!recv_json(sock, resp_meta) || resp_meta.value("status", "") != "OK") {
        std::cout << "[upload] server did not accept chunks for "
                  << local_full << "\n";
        file.close();
        return false;
    }

    int64_t sent_total = 0;
    int err = 0;
    for (int64_t i = 0; i < total_chunks; ++i) {
        size_t to_read = static_cast<size_t>(
            std::min<int64_t>(CHUNK_SIZE, file_size - sent_total)
        );
        std::vector<char> buffer(to_read);
        file.read(buffer.data(), to_read);
        size_t actually_read = file.gcount();

        nlohmann::json header = {
            {"chunk_index", i},
            {"size", (int64_t)actually_read}
        };
        send_json(sock, header);
        asio::write(sock, asio::buffer(buffer.data(), actually_read));

        nlohmann::json ack;
        if (!recv_json(sock, ack) ||
            ack.value("status","") != "OK" ||
            ack.value("ack",-1) != i) {
            std::cout << "\n[upload] error sending chunk " << i
                      << " of file " << local_full << "\n";
            err = 1;
            break;
        }

        sent_total += actually_read;
        double progress = (file_size > 0)
            ? (100.0 * sent_total / file_size)
            : 0.0;
        std::cout << "\r[upload] " << local_full.filename().string()
                  << " " << std::fixed << std::setprecision(1)
                  << progress << "%" << std::flush;
    }
    std::cout << "\n";

    file.close();
    return err == 0;
}

std::string hash_file_local(const fs::path& path)
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

struct LocalEntry {
    bool is_dir;
    std::uintmax_t size;
    std::string hash; // len pre súbory
};

void build_local_index(const fs::path& root_dir,
                       const fs::path& current,
                       std::map<std::string, LocalEntry>& out)
{
    for (const auto& entry : fs::directory_iterator(current)) {
        fs::path rel = fs::relative(entry.path(), root_dir);
        std::string rel_str = rel.generic_string();

        if (entry.is_directory()) {
            out[rel_str] = {true, 0, ""};
            build_local_index(root_dir, entry.path(), out);
        } else if (entry.is_regular_file()) {
            std::error_code ec;
            std::uintmax_t size = fs::file_size(entry.path(), ec);
            std::string h = hash_file_local(entry.path());
            out[rel_str] = {false, size, h};
        }
    }
}




int main(int argc, char* argv[]) {
    if (argc < 2) { std::cerr << "Wrong arguments\n"; return 1; }
    
    std::string ep = argv[1]; 
    auto pos = ep.rfind(':');
    if (pos == std::string::npos) { std::cerr << "Usage: [error] client <host:port>\n"; return 1; }
    std::string host_ip = ep.substr(0, pos);
    std::string port = ep.substr(pos + 1);
    

    auto [user, host] = splitUserIp(host_ip);

    //std::cout << "User: " << user << ", Host: " << host << "\n";


    try {
        asio::io_context io;
        tcp::resolver r(io);
        auto eps = r.resolve(host, port);
        tcp::socket sock(io);
        asio::connect(sock, eps);

        if (sodium_init() < 0) {
            std::cerr << "[client] sodium_init failed\n";
            return 1;
        }


        nlohmann::json auth;
        auth["cmd"] = "AUTH";
        auth["username"] = user;
        send_json(sock, auth);

        recv_json(sock, auth);
        if (auth.value("status", "ERROR") != "OK") {
            std::cerr << "[client] authentication failed: " << auth.value("message", "unknown error") << "\n";
            return 1;
        }

        if (auth.value("mode", "") == "public") {
            std::cout
                << "\n"
                << "╔══════════════════════════════════════════════╗\n"
                << "║           MiniDrive Client – PUBLIC          ║\n"
                << "╠══════════════════════════════════════════════╣\n"
                << "║  Connected to: " << host << ":" << port << "\n"
                << "╠══════════════════════════════════════════════╣\n"
                << "║  MODE: PUBLIC                                ║\n"
                << "║  - All files in this repository are          ║\n"
                << "║    visible to anyone connecting in public    ║\n"
                << "║    mode.                                     ║\n"
                << "║                                              ║\n"
                << "║  Do NOT store sensitive or private data here.║\n"
                << "╚══════════════════════════════════════════════╝\n\n";

            std::cout << "[client] connected to " << host << ":" << port << " (public mode)\n\n";

        } else {

            if (auth.value("next","") == "LOGIN") {
                std::cout << "Private mode. Login.\n\n";

                std::string pw;
                std::cout << "Your password: " << std::flush;
                std::system("stty -echo");
                std::getline(std::cin, pw);
                std::system("stty echo");
                std::cout << "\n\n";

                std::string pw_hash = argon2id_hex_b64salt(pw, auth.value("salt",""));
                // std::cout << "PW_hash: " << pw_hash << "\nSalt"<< auth.value("salt","") <<"\n";

                nlohmann::json login = {
                    {"cmd","LOGIN"},
                    {"username", user},
                    {"password", pw_hash}
                };
                send_json(sock, login);

                recv_json(sock, auth);
                if (auth.value("status","") != "OK") {
                    std::cerr << "[client] authentication failed: " << auth.value("message", "unknown error") << "\n";
                    return 1;
                }

                std::cout
                << "\n"
                << "╔══════════════════════════════════════════════╗\n"
                << "║           MiniDrive Client – PRIVATE         ║\n"
                << "╠══════════════════════════════════════════════╣\n"
                << "║  User:      " << user << "\n"
                << "║  Connected: " << host << ":" << port << "\n"
                << "╠══════════════════════════════════════════════╣\n"
                << "║  MODE: PRIVATE                               ║\n"
                << "║  - This is your personal repository.         ║\n"
                << "║  - Other users cannot see your files.        ║\n"
                << "║                                              ║\n"
                << "║  Type HELP to see available commands.        ║\n"
                << "╚══════════════════════════════════════════════╝\n\n";

                std::cout << "[client] connected to " << host << ":" << port
                        << " as '" << user << "' (private mode)\n\n";
                





            } else {
                std::cout << "Private mode. Registration.\n\n";
                
                std::string pw;
                std::cout << "Your new password: " << std::flush;
                std::system("stty -echo");
                std::getline(std::cin, pw);
                std::system("stty echo");
                std::cout << "\n\n";

                std::string pw_hash = argon2id_hex_b64salt(pw, auth.value("salt",""));
                //std::cout << "PW_hash: " << pw_hash << "\nSalt: " << auth.value("salt","") << "\n\n";

                nlohmann::json reg = {
                    {"cmd","REGISTER"},
                    {"username", user},
                    {"password", pw_hash}
                };
                send_json(sock, reg);

                recv_json(sock, auth);
                if (auth.value("status","") != "OK") {
                    std::cerr << "[client] authentication failed: " << auth.value("message", "unknown error") << "\n";
                    return 1;
                }

               std::cout
                << "\n"
                << "╔══════════════════════════════════════════════╗\n"
                << "║           MiniDrive Client – PRIVATE         ║\n"
                << "╠══════════════════════════════════════════════╣\n"
                << "║  User:      " << user << "\n"
                << "║  Connected: " << host << ":" << port << "\n"
                << "╠══════════════════════════════════════════════╣\n"
                << "║  MODE: PRIVATE                               ║\n"
                << "║  - This is your personal repository.         ║\n"
                << "║  - Other users cannot see your files.        ║\n"
                << "║                                              ║\n"
                << "║  Type HELP to see available commands.        ║\n"
                << "╚══════════════════════════════════════════════╝\n\n";

                std::cout << "[client] connected to " << host << ":" << port
                        << " as '" << user << "' (private mode)\n\n";

            }
        }


        std::string root = auth.value("root", "/");
        std::string dir = root;


        std::string line;
        while (true) {
            std::cout << "> ";
            if (!std::getline(std::cin, line)) break;
            if (line.empty()) continue;

            std::vector<std::string> toks;
            split_words(line, toks);
            if (toks.empty()) continue;


            std::string cmd = toks[0];
            std::string CMD = to_upper(cmd);

            if (CMD == "EXIT" || CMD == "QUIT" || CMD == "E" || CMD == "Q") {
                break;
            }
            // HELP (globálny aj HELP <cmd>)
            if (CMD == "HELP") {
                if (toks.size() == 1) { print_help_all(); continue; }
                std::string which = to_upper(toks[1]);
                print_help_cmd(which);
                continue;
            }

            // validácia počtu argov podľa <> / []
            size_t min_req=0, max_all=0;
            std::string usage;
            size_t have = (toks.size() >= 2) ? (toks.size()-1) : 0;
            if (!need_args(CMD, have, min_req, max_all, usage)) {
                if (usage.size()) std::cout << "\n[client] hint: " << usage << "\n\n";
                else std::cout << "\n[warning] unknown command. Type HELP.\n\n";
                continue;
            }

            // Naplnenie args (s defaultmi pre voliteľné)
            nlohmann::json args = nlohmann::json::object();

            if (CMD == "LIST") {
                args["path"] = (have >= 1) ? toks[1] : dir;

                if (!(args["path"].get<std::string>().starts_with("/"))) {
                    args["path"] = dir + "/" + args["path"].get<std::string>();
                } 
            } else if (CMD == "DELETE") {
                args["path"] = toks[1];
                if (!(args["path"].get<std::string>().starts_with("/"))) {
                    args["path"] = dir + "/" + args["path"].get<std::string>();
                } 
            } else if (CMD == "CD") {
                args["path"] = toks[1];
                std::string newPath = args["path"].get<std::string>();


                if (newPath == "..") {
                    dir = root;
                    std::cout << "\n[ok] changed directory to '" << dir << "' (root)\n\n";
                    continue;
                } else if (newPath == ".") {
                    std::cout << "\n[ok] stayed in directory '" << dir << "'\n\n";
                    continue;
                }
                if (!(args["path"].get<std::string>().starts_with("/"))) {
                    args["path"] = dir + "/" + args["path"].get<std::string>();
                } 

            } else if (CMD == "MKDIR") {
                args["path"] = toks[1];
                if (!(args["path"].get<std::string>().starts_with("/"))) {
                    args["path"] = dir + "/" + args["path"].get<std::string>();
                } 

            } else if (CMD == "RMDIR") {
                args["path"] = toks[1];

                if (!(args["path"].get<std::string>().starts_with("/"))) {
                    args["path"] = dir + "/" + args["path"].get<std::string>();
                } 

                if (!is_path_under(dir, args["path"].get<std::string>()) || dir == args["path"].get<std::string>()) {
                    dir = root;
                    continue;
                }
            } else if (CMD == "MOVE") {
                args["src"] = toks[1]; args["dst"] = toks[2];
                if (!(args["src"].get<std::string>().starts_with("/"))) {
                    args["src"] = dir + "/" + args["src"].get<std::string>();
                }
                if (!(args["dst"].get<std::string>().starts_with("/"))) {
                    args["dst"] = dir + "/" + args["dst"].get<std::string>();
                }
            } else if (CMD == "COPY") {
                args["src"] = toks[1]; args["dst"] = toks[2];
                if (!(args["src"].get<std::string>().starts_with("/"))) {
                    args["src"] = dir + "/" + args["src"].get<std::string>();
                }
                if (!(args["dst"].get<std::string>().starts_with("/"))) {
                    args["dst"] = dir + "/" + args["dst"].get<std::string>();
                }
                if (is_path_under(args["src"].get<std::string>(), args["dst"].get<std::string>())) {
                    std::cout << "\n[error] Cannot COPY: source path cannot be inside destination path!\nIt could cause recursive copying or other unintended behavior.\n\n";
                    continue; 
                }
            } else if (CMD == "DOWNLOAD") {
                args["remote"] = toks[1]; args["local"] = toks[2];

                if (!(args["remote"].get<std::string>().starts_with("/"))) {
                    args["remote"] = dir + "/" + args["remote"].get<std::string>();
                } 

                std::string local_path = args["local"].get<std::string>();
                if (!fs::exists(local_path) || !fs::is_directory(local_path)) {
                    std::cout << "\n[warning] Local path '" << local_path 
                            << "' must be an existing directory!\n\n";
                    continue; 
                }

                

                std::string filename = fs::path(args["remote"].get<std::string>()).filename().string();
                args["filename"] = filename;


                if (fs::exists(local_path + "/" + filename)) {
                    std::cout << "\n[warning] File '" << local_path + "/" + filename 
                            << "' already exists locally! Download aborted to prevent overwrite.\n\n";
                    continue; 
                }
                /* std::cout << "\n[info] Will download '" << args["remote"] 
                        << "' to directory '" << local_path 
                        << "' as '" << filename << "'\n\n"; */


            } else if (CMD == "UPLOAD") {
                args["local"] = toks[1]; args["remote"] = toks[2];

                if (!(args["remote"].get<std::string>().starts_with("/"))) {
                    args["remote"] = dir + "/" + args["remote"].get<std::string>();
                } 
                std::string local_path = args["local"].get<std::string>();
                if (!fs::exists(local_path) || fs::is_directory(local_path)) {
                    std::cout << "\n[warning] Local path '" << local_path 
                            << "' must be an existing file!\n\n";
                    continue; 
                }

                std::string filename = fs::path(args["local"].get<std::string>()).filename().string();
                args["filename"] = filename;


            } else if (CMD == "SYNC") {
                args["local"] = toks[1]; args["remote"] = toks[2];

                if (!(args["remote"].get<std::string>().starts_with("/"))) {
                    args["remote"] = dir + "/" + args["remote"].get<std::string>();
                } 
                if (is_path_under(args["local"].get<std::string>(), args["remote"].get<std::string>())) {
                    std::cout << "\n[error] Cannot SYNC: remote path cannot be inside local path!\nIt could cause recursive copying or other unintended behavior.\n\n";
                    continue; 
                }

                std::string local_path = args["local"].get<std::string>();
                if (!fs::exists(local_path) || !fs::is_directory(local_path)) {
                    std::cout << "\n[warning] Local path '" << local_path 
                            << "' must be an existing directory!\n\n";
                    continue; 
                }

            } else {
                std::cout << "[warning] unknown command. Type HELP.\n";
                continue;
            }

            // Odoslanie žiadosti
            nlohmann::json req = {{"client_port", port},{"cmd", CMD}, {"args", args}, {"root", root}};
            send_json(sock, req);
 
            nlohmann::json resp;
            if (!recv_json(sock, resp)) { std::cout << "[error] server closed\n"; break; }

            if (CMD == "LIST") {
                if (resp.value("status", "ERROR") == "OK") {
                    std::string msg = resp.value("data", "");

                    if (msg.empty()) {
                        std::cout << "\n[ok] OK\n\nadresár je prázdny\n\n";
                    } else {
                        std::cout << "\n[ok] OK\n\n";

                        try {
                            // 🔹 Skús parse-nuť obsah "data" (je to string, ale vo formáte JSON)
                            nlohmann::json files = nlohmann::json::parse(msg);

                            if (files.is_array()) {
                                std::cout << std::left << std::setw(30) << "Názov"
                                        << std::setw(12) << "Typ"
                                        << std::setw(20) << "Veľkosť" << "\n";
                                std::cout << std::string(55, '-') << "\n";

                                for (const auto& file : files) {
                                    std::string name = file.value("name", "");
                                    std::string type = file.value("type", "");
                                    std::string size = file.value("size", "-");

                                    std::cout << std::left
                                            << std::setw(30) << name
                                            << std::setw(10) << type
                                            << std::right << std::setw(15)
                                            << formatSize(size)
                                            << "\n";
                                }
                                std::cout << std::string(55, '-') << "\n\n";
                            } else {
                                // Ak to nie je pole, vypíš ako text
                                std::cout << msg << "\n";
                            }
                        } catch (const std::exception& e) {
                            // 🔹 Ak to nie je validný JSON, vypíš ako obyčajný text
                            std::cout << msg << "\n";
                        }
                    }
                } else {
                    std::cout << "\n[error]\n"
                            << resp.value("data", "") << "\n\n";
                }
            }
            else if (CMD == "CD") {
                if (resp.value("status", "ERROR") == "OK") {
                    dir = args["path"].get<std::string>();
                    std::cout << "\n[ok] changed directory to '" << dir << "'\n\n";
                } else {
                    std::cout << "\n[error] failed to change directory to '" << args["path"].get<std::string>() << "'\n"
                    << "Reason: " << resp.value("message", "") << "\n\n";
                }
            }
            else if (CMD == "MKDIR") {
                if (resp.value("status", "ERROR") == "OK") {
                    std::cout << "\n[ok] directory created: '" << args["path"].get<std::string>() << "'\n\n";
                } else {
                    std::cout << "\n[error] failed to create directory '" << args["path"].get<std::string>() << "'\n"
                    << "Reason: " << resp.value("message", "") << "\n\n";
                }
            }
            else if (CMD == "RMDIR") {

                if (resp.value("status", "ERROR") == "OK") {
                    std::cout << "\n[ok] directory removed: '" << args["path"].get<std::string>() << "'\n\n";
                } else {
                    std::cout << "\n[error] failed to remove directory '" << args["path"].get<std::string>() << "'\n"
                    << "Reason: " << resp.value("message", "") << "\n\n";
                }
            }
            else if (CMD == "DELETE") {
                if (resp.value("status", "ERROR") == "OK") {
                    std::cout << "\n[ok] file deleted: '" << args["path"].get<std::string>() << "'\n\n";
                } else {
                    std::cout << "\n[error] failed to delete file '" << args["path"].get<std::string>() << "'\n"
                    << "Reason: " << resp.value("message", "") << "\n\n";
                }
            } else if (CMD == "MOVE") {
                if (resp.value("status", "ERROR") == "OK") {
                    std::cout << "\n[ok] moved/renamed from '" << args["src"].get<std::string>()
                              << "' to '" << args["dst"].get<std::string>() << "'\n\n";
                } else {
                    std::cout << "\n[error] failed to move/rename from '" << args["src"].get<std::string>()
                              << "' to '" << args["dst"].get<std::string>() << "'\n"
                              << "Reason: " << resp.value("message", "") << "\n\n";
                }
            } else if (CMD == "COPY") {
                if (resp.value("status", "ERROR") == "OK") {
                    std::cout << "\n[ok] copied from '" << args["src"].get<std::string>()
                              << "' to '" << args["dst"].get<std::string>() << "'\n\n";
                } else {
                    std::cout << "\n[error] failed to copy from '" << args["src"].get<std::string>()
                              << "' to '" << args["dst"].get<std::string>() << "'\n"
                              << "Reason: " << resp.value("message", "") << "\n\n";
                }
            } else if (CMD == "DOWNLOAD") {
                if (resp.value("status", "ERROR") == "OK") {
                    std::cout << "\n[ok] downloaded remote '" << args["remote"].get<std::string>()
                              << "' to local '" << args["local"].get<std::string>() << "' as '" << args["filename"].get<std::string>() << "'\n";
                    std::cout << "\n[info] Starting download file '" << args["remote"].get<std::string>() << "' of size " << resp.value("size", 0) << " bytes in " << resp.value("total_chunks", 0) << " chunks.\n\n";
                            // --- 🔹 prijímanie chunkov po potvrdení OK ---
                    int64_t file_size = resp.value("size", 0);
                    int64_t chunk_size = resp.value("chunk_size", 0);
                    int64_t total_chunks = resp.value("total_chunks", 0);

                    std::string local_dir = args["local"].get<std::string>();
                    std::string filename = args["filename"].get<std::string>();
                    std::string out_path = (fs::path(local_dir) / filename).string();

                    std::ofstream out(out_path, std::ios::binary);
                    if (!out.is_open()) {
                        std::cout << "[error] cannot open local file for writing: " << out_path << "\n";
                        continue;
                    }

                    auto start_time = std::chrono::steady_clock::now();

                    int64_t received_total = 0;
                    for (int64_t i = 0; i < total_chunks; ++i) {
                        nlohmann::json header;
                        if (!recv_json(sock, header)) {
                            std::cout << "[error] failed to receive header for chunk " << i << "\n";
                            break;
                        }

                        int64_t chunk_index = header.value("chunk_index", 0);
                        int64_t bytes_expected = header.value("size", 0);

                        // --- čítaj presne bytes_expected bajtov ---
                        std::vector<char> buffer(bytes_expected);
                        asio::error_code ec;
                        int64_t bytes_read_total = 0;
                        while (bytes_read_total < bytes_expected) {
                            int64_t n = sock.read_some(asio::buffer(buffer.data() + bytes_read_total,
                                                                bytes_expected - bytes_read_total), ec);
                            if (ec) {
                                std::cout << "[error] socket read error during chunk " << chunk_index
                                        << ": " << ec.message() << "\n";
                                break;
                            }
                            bytes_read_total += n;
                        }

                        if (bytes_read_total != bytes_expected) {
                            std::cout << "[warning] incomplete chunk " << chunk_index
                                    << " (" << bytes_read_total << "/" << bytes_expected << ")\n";
                        }

                        // zapíš chunk
                        out.write(buffer.data(), bytes_read_total);
                        received_total += bytes_read_total;

                        // potvrď chunk serveru
                        nlohmann::json ack = {{"ack", static_cast<int32_t>(chunk_index)}, {"status", "OK"}};
                        send_json(sock, ack);

                        // priebežný výpis
                        double progress = (file_size > 0) ? (100.0 * received_total / file_size) : 0.0;
                        std::cout << "\r[download] chunk " << (i + 1) << "/" << total_chunks
                                << " (" << std::fixed << std::setprecision(1) << progress << "%)" << std::flush;
                    }
                    auto end_time = std::chrono::steady_clock::now();
                    std::chrono::duration<double> elapsed = end_time - start_time;
                    double seconds = elapsed.count();

                    double speed_mbps = (received_total * 8.0) / (seconds * 1024.0 * 1024.0); // v Mbit/s
                    double speed_mb_s = (received_total / (1024.0 * 1024.0)) / seconds;       // v MB/s

                    out.close();
                    std::cout << "\n\n[ok] Download completed successfully -> " << out_path << "\n\n";
                    std::cout << "[info] Total time: " << std::fixed << std::setprecision(2) << seconds << " s"
                                    << " (" << speed_mb_s << " MB/s, " << speed_mbps << " Mbit/s)\n\n";
                } 
                else {
                    std::cout << "\n[error] failed to download remote '" << args["remote"].get<std::string>()
                              << "' to local '" << args["local"].get<std::string>() << "'\n"
                              << "Reason: " << resp.value("message", "") << "\n\n";
                }
            } else if (CMD == "UPLOAD") {
                if (resp.value("status", "") != "OK") {
                    std::cout << "\n[error] server rejected upload: "
                            << resp.value("message", "") << "\n\n";
                    continue;
                }
                const size_t CHUNK_SIZE = 64 * 1024; // 64 KB chunky
                std::ifstream file(args["local"].get<std::string>(), std::ios::binary);
                if (!file.is_open()) {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "ERROR"}, {"message", "Cannot open file"}});
                    continue;
                }

                int64_t file_size = std::filesystem::file_size(args["local"].get<std::string>());
                int64_t total_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

                std::cout << "\n[info] Starting upload file '" << args["local"].get<std::string>() << "' of size " << file_size << " bytes in " << total_chunks << " chunks.\n\n";




                auto start_time = std::chrono::steady_clock::now();
                send_json(sock, {
                    {"cmd", "UPLOAD"},
                    {"status", "OK"},
                    {"size", file_size},
                    {"chunk_size", CHUNK_SIZE},
                    {"total_chunks", total_chunks}
                });

                recv_json(sock, resp);
                if (resp.value("status", "") != "OK") {
                    std::cout << "\n[error] server rejected upload: "
                            << resp.value("message", "") << "\n\n";
                    file.close();
                    continue;
                } else {
                    std::cout << "[info] Server accepted upload. Sending data...\n\n";
                }

                int64_t sent_total = 0;
                int err = 0;
                for (int64_t i = 0; i < total_chunks; ++i) {
                    size_t to_read = static_cast<size_t>(std::min<int64_t>(CHUNK_SIZE, file_size - sent_total));
                    std::vector<char> buffer(to_read);
                    file.read(buffer.data(), to_read);
                    size_t actually_read = file.gcount();

                    // send header
                    nlohmann::json header = {
                        {"chunk_index", i},
                        {"size", actually_read}
                    };
                    send_json(sock, header);

                    // send data
                    asio::write(sock, asio::buffer(buffer.data(), actually_read));

                    // wait for ack
                    nlohmann::json ack;
                    if (!recv_json(sock, ack)) {
                        std::cout << "\n\n[error] failed to receive ack for chunk " << i << "\n";
                        err = 1;
                        break;
                    }
                    std::string status = ack.value("status", "ERROR");
                    if (status != "OK") {
                        std::cout << "[error] server reported error for chunk " << i << ": "
                                << ack.value("message", "") << "\n";
                        err = 1;
                        break;
                    }

                    sent_total += actually_read;

                    // priebežný výpis
                    double progress = (file_size > 0) ? (100.0 * sent_total / file_size) : 0.0;
                    std::cout << "\r[upload] chunk " << (i + 1) << "/" << total_chunks
                            << " (" << std::fixed << std::setprecision(1) << progress << "%)" << std::flush;
                }
                auto end_time = std::chrono::steady_clock::now();
                std::chrono::duration<double> elapsed = end_time - start_time;
                double seconds = elapsed.count();

                double speed_mbps = (sent_total * 8.0) / (seconds * 1024.0 * 1024.0); // v Mbit/s
                double speed_mb_s = (sent_total / (1024.0 * 1024.0)) / seconds;       // v MB/s

                file.close();
                if (!err) {
                    std::cout << "\n\n[ok] Upload completed successfully -> " << (fs::path(args["remote"].get<std::string>()) / fs::path(args["local"].get<std::string>()).filename().string()).string() << "\n\n";
                    std::cout << "[info] Total time: " << std::fixed << std::setprecision(2) << seconds << " s"
                                    << " (" << speed_mb_s << " MB/s, " << speed_mbps << " Mbit/s)\n\n";
                } else {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "ERROR"}, {"message", "Upload interrupted"}});
                }
            } else if (CMD == "SYNC") {

                if (resp.value("status", "") != "OK") {
                    std::cout << "[error] Server error: "
                            << resp.value("message", "unknown error") << "\n";
                    continue;
                }
                auto sync_start = std::chrono::steady_clock::now();
                fs::path local_path = args["local"].get<std::string>();
                std::string server_path = args["remote"].get<std::string>();

                int deleted_files_count = 0;
                int deleted_dirs_count  = 0;
                int created_dirs_count  = 0;
                int uploaded_files_count = 0;

                auto entries_json = resp.value("entries", nlohmann::json::array());

                struct RemoteEntry {
                    bool is_dir;
                    std::uintmax_t size;
                    std::string hash;
                };

                std::map<std::string, RemoteEntry> remote_index;

                for (auto& e : entries_json) {
                    std::string rel = e.value("rel", "");
                    std::string type = e.value("type", "");

                    if (type == "dir") {
                        remote_index[rel] = {true, 0, ""};
                    } else if (type == "file") {
                        std::uintmax_t size = e.value("size", 0);
                        std::string hash = e.value("hash", "");
                        remote_index[rel] = {false, size, hash};
                    }
                }


                std::map<std::string, LocalEntry> local_index;
                build_local_index(local_path, local_path, local_index);


                struct Op {
                    enum Type { MKDIR, DELETE_FILE, DELETE_DIR, UPLOAD_FILE } type;
                    std::string rel; // relatívna cesta
                };

                std::vector<Op> ops;
                std::vector<std::string> skipped_files;

                for (const auto& [rel, r] : remote_index) {
                    if (!local_index.count(rel)) {
                        if (r.is_dir) {
                            ops.push_back({Op::DELETE_DIR, rel});
                        } else {
                            ops.push_back({Op::DELETE_FILE, rel});
                        }
                    }
                }

                // 4b) vytvorenie adresárov + upload / update súborov
                for (const auto& [rel, l] : local_index) {
                    auto it = remote_index.find(rel);

                    if (l.is_dir) {
                        // LOKÁLNE: priečinok
                        if (it == remote_index.end()) {
                            // na serveri neexistuje -> vytvoríme priečinok
                            ops.push_back({Op::MKDIR, rel});
                        } else if (!it->second.is_dir) {
                            // na serveri je na tej istej ceste súbor -> zmaž súbor, potom vytvor priečinok
                            ops.push_back({Op::DELETE_FILE, rel});
                            ops.push_back({Op::MKDIR, rel});
                        }
                        // ak je na serveri tiež priečinok -> nič netreba
                    } else {
                        // LOKÁLNE: súbor
                        if (it == remote_index.end()) {
                            // súbor na serveri neexistuje -> stačí upload
                            ops.push_back({Op::UPLOAD_FILE, rel});
                        } else if (it->second.is_dir) {
                            // na serveri je priečinok, lokálne súbor -> zmažeme priečinok, potom uploadneme súbor
                            ops.push_back({Op::DELETE_DIR, rel});
                            ops.push_back({Op::UPLOAD_FILE, rel});
                        } else if (it->second.hash != l.hash) {
                            // súbor existuje na oboch stranách, ale hash je iný -> zmaz a znova uploadni
                            ops.push_back({Op::DELETE_FILE, rel});
                            ops.push_back({Op::UPLOAD_FILE, rel});

                            // (voliteľný debug)
                            // std::cout << "[sync] changed file: " << rel << "\n";
                        } else {
                            // hash je rovnaký -> SKIPPED (netreba nič robiť)
                            skipped_files.push_back(rel);
                        }
                    }
                }

                std::cout << "\n[info] Planned operations:\n";
                for (const auto& op : ops) {
                    std::string op_name;
                    switch (op.type) {
                        case Op::MKDIR: op_name = "MKDIR      "; break;
                        case Op::DELETE_FILE: op_name = "DELETE FILE"; break;
                        case Op::DELETE_DIR: op_name = "DELETE DIR "; break;
                        case Op::UPLOAD_FILE: op_name = "UPLOAD FILE"; break;
                    }
                    fs::path remote_full = fs::path(server_path) / fs::path(op.rel);
                    std::cout << "  " << op_name << " : " << remote_full.generic_string() << "\n";
                }
                if (ops.empty()) {
                    std::cout << "  (no operations needed, remote is already sync)\n";
                } else {
                    std::cout << "\n";
                }

                // DELETE súbory
                for (const auto& op : ops) {
                    if (op.type != Op::DELETE_FILE) continue;
                    fs::path remote_full = fs::path(server_path) / fs::path(op.rel);
                    nlohmann::json req_del = {
                        {"cmd", "DELETE"},
                        {"root", root},
                        {"args", {
                            {"path", remote_full.generic_string()}
                        }}
                    };
                    send_json(sock, req_del);
                    nlohmann::json r;
                    recv_json(sock, r);
                }

                // DELETE priečinky (RMDIR) 
                std::vector<std::string> dirs_to_delete;
                for (const auto& op : ops) {
                    if (op.type == Op::DELETE_DIR) {
                        dirs_to_delete.push_back(op.rel);
                    }
                }
                std::sort(dirs_to_delete.begin(), dirs_to_delete.end(),
                        [](const std::string& a, const std::string& b){
                            return a.size() > b.size(); // dlhšia (hlbšia) najprv
                        });

                for (const auto& rel : dirs_to_delete) {
                    fs::path remote_full = fs::path(server_path) / fs::path(rel);
                    nlohmann::json req_rmdir = {
                        {"cmd", "RMDIR"},
                        {"root", root},
                        {"args", {
                            {"path", remote_full.generic_string()}
                        }}
                    };
                    send_json(sock, req_rmdir);
                    nlohmann::json r;
                    recv_json(sock, r);
                }

                //  MKDIR
                for (const auto& op : ops) {
                    if (op.type != Op::MKDIR) continue;
                    fs::path remote_full = fs::path(server_path) / fs::path(op.rel);
                    nlohmann::json req_mkdir = {
                        {"cmd", "MKDIR"},
                        {"root", root},
                        {"args", {
                            {"path", remote_full.generic_string()}
                        }}
                    };
                    send_json(sock, req_mkdir);
                    nlohmann::json r;
                    recv_json(sock, r);
                }


                // UPLOAD súbory – teraz pridáme
                for (const auto& op : ops) {
                    if (op.type != Op::UPLOAD_FILE) continue;

                    // plná lokálna cesta k súboru
                    fs::path local_full = local_path / fs::path(op.rel);
                    // cieľový adresár na serveri
                    fs::path remote_dir_for_file =
                        fs::path(server_path) / fs::path(op.rel).parent_path();

                    if (!fs::exists(local_full) || fs::is_directory(local_full)) {
                        std::cout << "[info] skip (not a file): " << local_full << "\n";
                        continue;
                    }

                    if (do_upload(sock, port, root, local_full, remote_dir_for_file)) {
                        std::cout << "[ok] uploaded " << local_full
                                << " -> " << remote_dir_for_file << "\n";
                    } else {
                        std::cout << "[error] upload FAILED for " << local_full << "\n";
                    }
                }

                // --- SUMÁR SYNCU ---

                std::cout << "\n";
                // skipped files (rovnaký hash)
                if (!skipped_files.empty()) {
                    std::cout << "[info] skipped files (unchanged, hash OK):\n";
                    for (const auto& rel : skipped_files) {
                        fs::path remote_full = fs::path(server_path) / fs::path(rel);
                        std::cout << "  " << remote_full.generic_string() << "\n";
                    }
                    std::cout << "\n[info] sync -> skipped " << skipped_files.size() << " file(s)\n\n";
                } else {
                    std::cout << "[info] skipped files: none\n";
                }

                std::cout << "\n[info] Synchronization finished.\n";

                auto sync_end = std::chrono::steady_clock::now();
                std::chrono::duration<double> elapsed = sync_end - sync_start;
                double seconds = elapsed.count();
                

                                // --- spočítanie štatistík z ops ---
                for (const auto& op : ops) {
                    switch (op.type) {
                        case Op::DELETE_FILE: deleted_files_count++; break;
                        case Op::DELETE_DIR:  deleted_dirs_count++;  break;
                        case Op::MKDIR:       created_dirs_count++;  break;
                        case Op::UPLOAD_FILE: uploaded_files_count++; break;
                    }
                }

                int skipped_count = static_cast<int>(skipped_files.size());

                std::cout << "\n========================================\n";
                std::cout << " SYNC summary\n";
                std::cout << "  Local : " << local_path << "\n";
                std::cout << "  Remote: " << server_path << "\n";
                std::cout << "----------------------------------------\n";
                std::cout << "  Created directories : " << created_dirs_count  << "\n";
                std::cout << "  Deleted directories : " << deleted_dirs_count  << "\n";
                std::cout << "  Deleted files       : " << deleted_files_count << "\n";
                std::cout << "  Uploaded files      : " << uploaded_files_count << "\n";
                std::cout << "  Skipped (unchanged) : " << skipped_count       << "\n";
                std::cout << "----------------------------------------\n";
                std::cout << "  Total time          : "
                        << std::fixed << std::setprecision(2) << seconds << " s\n";
                std::cout << "========================================\n\n";

                

            } else {
                std::string status = resp.value("status", "ERROR");
                std::string message = resp.value("message", "");
                if (status == "OK") {
                    std::cout << "\n[ok] " << message << "\n\n";
                } else {
                    std::cout << "\n[error] " << message << "\n\n";
                }
            }
        }

        std::cout << "[client] disconnecting ...\n\n";
    } catch (const std::exception& e) {
        std::cerr << "[error] fatal: " << e.what() << "\n";
        return 1;
    }
}