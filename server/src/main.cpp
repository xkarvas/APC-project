// server/main.cpp
#define ASIO_STANDALONE
#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <cstring>

#include <filesystem>
namespace fs = std::filesystem;

using asio::ip::tcp;

// --- big-endian helpers (bez arpa/inet) ---
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
        fs::path rootPath = fs::weakly_canonical(root);
        fs::path targetPath = fs::weakly_canonical(path);

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

static void handle_client(tcp::socket sock) {
    try {
        std::cout << "[server] client connected from " << sock.remote_endpoint() << "\n";
        while (true) {
            nlohmann::json req;
            if (!recv_json(sock, req)) break;

            const std::string cmd = req.value("cmd", "");
            const auto args = req.value("args", nlohmann::json::object());
            const auto root = req.value("root", "");
            // std::cout << "[server] cmd=" << cmd << " args=" << args.dump() << "\n";

            
            if (cmd == "LIST") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","LIST"},{"status","ERROR"},{"code",2},{"message", "Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] list -> access denied, path: " << path << ", root: " << root << "\n";
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
                            item["size"] = "-";
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
                    std::cout << "[ok] list -> " << "path: " << path <<"\n";

                } catch (const std::exception& e) {
                    result = std::string("Error: ") + e.what();
                    send_json(sock, {{"cmd","LIST"},{"status","ERROR"},{"code",1},{"message","LIST command failed"},{"data", result}});
                    std::cout << "[error] list ->" << result << std::endl;
                }               // TODO: implement LIST command
            } else if (cmd == "CD") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] cd -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(path)) {
                        if (std::filesystem::is_directory(path)) {
                            // Je to priečinok
                            send_json(sock, {{"cmd","CD"},{"status","OK"},{"code",0},{"path", path}});
                            std::cout << "[ok] cd -> ok, changed to '" << path << "'" << "\n";

                        } else {
                            send_json(sock, {{"cmd","CD"},{"status","WARNING"},{"code",-1},{"path", path},{"message","Not a directory"}});
                            std::cout << "[error] cd -> not a directory, path: '" << path << "'\n";
                        }
                    } else {
                        // neexistuje
                        send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",1},{"path", path},{"message","Directory does not exist"}});
                        std::cout << "[error] cd -> directory does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",1},{"path", path},{"message","Unknown error"}});
                    std::cout << "[error] cd -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "MKDIR") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] mkdir -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(path)) {
                        send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",1},{"message","Directory already exists"}});
                        std::cout << "[error] mkdir -> directory already exists, path: '" << path << "'\n";
                    } else {
                        std::filesystem::create_directories(path);
                        send_json(sock, {{"cmd","MKDIR"},{"status","OK"},{"code",0},{"message","Directory created"}});
                        std::cout << "[ok] mkdir -> created directory at '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",1},{"message","Failed to create directory"}});
                    std::cout << "[error] mkdir -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "RMDIR") {
                std::string path = args.value("path", "");
                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] rmdir -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }
                try {
                    if (std::filesystem::exists(path)) {
                        if (!std::filesystem::is_directory(path)) {
                            send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Path is not a directory"}});
                            std::cout << "[error] rmdir -> path is not a directory, path: '" << path << "'\n";
                            continue;
                        }
                        std::filesystem::remove_all(path);
                        send_json(sock, {{"cmd","RMDIR"},{"status","OK"},{"code",0},{"message","Directory removed"}});
                        std::cout << "[ok] rmdir -> removed directory at '" << path << "'\n";
                    } else {
                        send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Directory does not exist"}});
                        std::cout << "[error] rmdir -> directory does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Failed to remove directory"}});
                    std::cout << "[error] rmdir -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "DELETE") {
                std::string path = args.value("path", "");
                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] delete -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }
                try {
                    if (std::filesystem::exists(path)) {
                        if (std::filesystem::is_directory(path)) {
                            send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","Path is directory not a file"}});
                            std::cout << "[error] delete -> path is not a file, path: '" << path << "'\n";
                            continue;
                        }
                        std::filesystem::remove(path);
                        send_json(sock, {{"cmd","DELETE"},{"status","OK"},{"code",0},{"message","File deleted"}});
                        std::cout << "[ok] delete -> removed file at '" << path << "'\n";
                    } else {
                        send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","File does not exist"}});
                        std::cout << "[error] delete -> file does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","Failed to delete file"}});
                    std::cout << "[error] delete -> exception: " << e.what() << "\n";
                }
            }
            
            
            else {
                send_json(sock, {{"cmd", cmd}, {"status","ERROR"}, {"code",1}, {"message","Unknown command"}});
                std::cout << "[error] unknown command: " << cmd << "\n";
            }
        } 
    } catch (const std::exception& e) {
        std::cout << "[server] exception: " << e.what() << "\n";
    }
    std::cout << "[server] client disconnected\n";
}

int main(int argc, char* argv[]) {
    int port = 5050;
    // mini-args: ./server --port 5050
    for (int i = 1; i + 1 < argc; ++i) {
        std::string k = argv[i], v = argv[i+1];
        if (k == "--port") port = std::stoi(v);
    }

    try {
        asio::io_context io;
        tcp::acceptor acc(io, tcp::endpoint(tcp::v4(), (unsigned short)port)); // 0.0.0.0:<port>
        std::cout << "[server] listening on 0.0.0.0:" << port << "\n";

        while (true) {
            tcp::socket sock(io);
            acc.accept(sock);                             // blokujúci accept
            std::thread(handle_client, std::move(sock)).detach(); // vlákno na klienta
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] fatal: " << e.what() << "\n";
        return 1;
    }
}