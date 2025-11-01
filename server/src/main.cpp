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
#include <fstream>


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

static void handle_client(tcp::socket sock) {
    try {
        std::cout << "[server] client connected from " << sock.remote_endpoint() << "\n";
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
                    std::cout << "[error] " << client_port << " list -> access denied, path: " << path << ", root: " << root << "\n";
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
                    std::cout << "[ok] " << client_port << " list -> " << "path: " << path <<"\n";

                } catch (const std::exception& e) {
                    result = std::string("Error: ") + e.what();
                    send_json(sock, {{"cmd","LIST"},{"status","ERROR"},{"code",1},{"message","LIST command failed"},{"data", result}});
                    std::cout << "[error] " << client_port << " list ->" << result << std::endl;
                }               // TODO: implement LIST command
            } else if (cmd == "CD") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << client_port << " cd -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(path)) {
                        if (std::filesystem::is_directory(path)) {
                            // Je to priečinok
                            send_json(sock, {{"cmd","CD"},{"status","OK"},{"code",0},{"path", path}});
                            std::cout << "[ok] " << client_port << " cd -> ok, changed to '" << path << "'" << "\n";

                        } else {
                            send_json(sock, {{"cmd","CD"},{"status","WARNING"},{"code",-1},{"path", path},{"message","Not a directory"}});
                            std::cout << "[error] " << client_port << " cd -> not a directory, path: '" << path << "'\n";
                        }
                    } else {
                        // neexistuje
                        send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",1},{"path", path},{"message","Directory does not exist"}});
                        std::cout << "[error] " << client_port << " cd -> directory does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","CD"},{"status","ERROR"},{"code",1},{"path", path},{"message","Unknown error"}});
                    std::cout << "[error] " << client_port << " cd -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "MKDIR") {
                std::string path = args.value("path", "");

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << client_port << " mkdir -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(path)) {
                        send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",1},{"message","Directory already exists"}});
                        std::cout << "[error] " << client_port << " mkdir -> directory already exists, path: '" << path << "'\n";
                    } else {
                        std::filesystem::create_directories(path);
                        send_json(sock, {{"cmd","MKDIR"},{"status","OK"},{"code",0},{"message","Directory created"}});
                        std::cout << "[ok] " << client_port << " mkdir -> created directory at '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","MKDIR"},{"status","ERROR"},{"code",1},{"message","Failed to create directory"}});
                    std::cout << "[error] " << client_port << " mkdir -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "RMDIR") {
                std::string path = args.value("path", "");
                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << client_port << " rmdir -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }
                try {
                    if (std::filesystem::exists(path)) {
                        if (!std::filesystem::is_directory(path)) {
                            send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Path is not a directory"}});
                            std::cout << "[error] " << client_port << " rmdir -> path is not a directory, path: '" << path << "'\n";
                            continue;
                        }
                        std::filesystem::remove_all(path);
                        send_json(sock, {{"cmd","RMDIR"},{"status","OK"},{"code",0},{"message","Directory removed"}});
                        std::cout << "[ok] " << client_port << " rmdir -> removed directory at '" << path << "'\n";
                    } else {
                        send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Directory does not exist"}});
                        std::cout << "[error] " << client_port << " rmdir -> directory does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","RMDIR"},{"status","ERROR"},{"code",1},{"message","Failed to remove directory"}});
                    std::cout << "[error] " << client_port << " rmdir -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "DELETE") {
                std::string path = args.value("path", "");
                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] " << client_port << " delete -> access denied, path: " << path << ", root: " << root << "\n";
                    continue;
                }
                try {
                    if (std::filesystem::exists(path)) {
                        if (std::filesystem::is_directory(path)) {
                            send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","Path is directory not a file"}});
                            std::cout << "[error] " << client_port << " delete -> path is not a file, path: '" << path << "'\n";
                            continue;
                        }
                        std::filesystem::remove(path);
                        send_json(sock, {{"cmd","DELETE"},{"status","OK"},{"code",0},{"message","File deleted"}});
                        std::cout << "[ok] " << client_port << " delete -> removed file at '" << path << "'\n";
                    } else {
                        send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","File does not exist"}});
                        std::cout << "[error] " << client_port << " delete -> file does not exist, path: '" << path << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","DELETE"},{"status","ERROR"},{"code",1},{"message","Failed to delete file"}});
                    std::cout << "[error] " << client_port << " delete -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "MOVE") {
                std::string src = args.value("src", "");
                std::string dst = args.value("dst", "");

                if (!is_path_under_root(root, src) || !is_path_under_root(root, dst)) {
                    send_json(sock, {{"cmd","MOVE"},{"status","ERROR"},{"code",2},{"message","Access denied: source or destination path is outside root (" + root + ")"}});
                    std::cout << "[error] " << client_port << " move -> access denied, src: " << src << ", dst: " << dst << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (std::filesystem::exists(src)) {
                        std::filesystem::rename(src, dst);
                        send_json(sock, {{"cmd","MOVE"},{"status","OK"},{"code",0},{"message","Move/Rename successful"}});
                        std::cout << "[ok] " << client_port << " move -> moved/renamed from '" << src << "' to '" << dst << "'\n";
                    } else {
                        send_json(sock, {{"cmd","MOVE"},{"status","ERROR"},{"code",1},{"message","Source path does not exist"}});
                        std::cout << "[error] " << client_port << " move -> source path does not exist, src: '" << src << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","MOVE"},{"status","ERROR"},{"code",1},{"message","Failed to move/rename"}});
                    std::cout << "[error] " << client_port << " move -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "COPY") {
                std::string src = args.value("src", "");
                std::string dst = args.value("dst", "");

                if (!is_path_under_root(root, src) || !is_path_under_root(root, dst)) {
                    send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",2},{"message","Access denied: source or destination path is outside root (" + root + ")"}});
                    std::cout << "[error] " << client_port << " copy -> access denied, src: " << src << ", dst: " << dst << ", root: " << root << "\n";
                    continue;
                }

                try {
                    if (!fs::exists(src)) {
                        send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",1},{"message","Source does not exist"},{"data", ""}});
                        std::cout << "[error] " << client_port << " copy -> source does not exist: '" << src << "'\n";
                        continue;
                    }

                    // 🔒 ochrana proti kopírovaniu do svojho podpriečinka
                    fs::path srcPath = fs::weakly_canonical(src);
                    fs::path dstPath = fs::weakly_canonical(dst);

                    if (dstPath.string().find(srcPath.string()) == 0) {
                        send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",3},
                                        {"message","Destination is inside source directory (would cause infinite recursion)"},{"data", ""}});
                        std::cout << "[error] " << client_port << " copy -> destination is inside source directory\n";
                        continue;
                    }
                    if (std::filesystem::exists(src)) {
                        if (std::filesystem::is_directory(src)) {
                            std::filesystem::copy(src, dst, fs::copy_options::recursive);
                        } else {
                            std::filesystem::copy_file(src, dst);
                        }
                        send_json(sock, {{"cmd","COPY"},{"status","OK"},{"code",0},{"message","Copy successful"}});
                        std::cout << "[ok] " << client_port << " copy -> copied from '" << src << "' to '" << dst << "'\n";
                    } else {
                        send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",1},{"message","Source path does not exist"}});
                        std::cout << "[error] " << client_port << " copy -> source path does not exist, src: '" << src << "'\n";
                    }
                }
                catch (const std::exception& e) {
                    send_json(sock, {{"cmd","COPY"},{"status","ERROR"},{"code",1},{"message","Failed to copy"}});
                    std::cout << "[error] " << client_port << " copy -> exception: " << e.what() << "\n";
                }
            } else if (cmd == "DOWNLOAD") {
                std::string path = args.value("remote", "");

                if (!std::filesystem::exists(path) || !std::filesystem::is_regular_file(path)) {
                    send_json(sock, {{"cmd", "DOWNLOAD"}, {"status", "ERROR"}, {"message", "File not found"}});
                    continue;
                }

                const size_t CHUNK_SIZE = 64 * 1024; // 64 KB chunky
                std::ifstream file(path, std::ios::binary);
                if (!file.is_open()) {
                    send_json(sock, {{"cmd", "DOWNLOAD"}, {"status", "ERROR"}, {"message", "Cannot open file"}});
                    continue;
                }

                int64_t file_size = std::filesystem::file_size(path);
                int64_t total_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

                std::cout << "[server] Starting download file '" << path << "' of size " << file_size << " bytes in " << total_chunks << " chunks. From client port: " << client_port << "\n";
                send_json(sock, {
                    {"cmd", "DOWNLOAD"},
                    {"status", "OK"},
                    {"size", file_size},
                    {"chunk_size", CHUNK_SIZE},
                    {"total_chunks", total_chunks}
                });

                char buffer[CHUNK_SIZE];
                for (size_t i = 0; i < total_chunks; ++i) {
                    file.read(buffer, CHUNK_SIZE);
                    std::streamsize bytes_read = file.gcount();
                    if (bytes_read <= 0) break;

                    // hlavička pre chunk
                    nlohmann::json header = {
                        {"chunk_index", static_cast<int64_t>(i)},
                        {"size", static_cast<int64_t>(bytes_read)}
                    };
                    send_json(sock, header);

                    // Pošli dáta chunku
                    asio::write(sock, asio::buffer(buffer, bytes_read));

                    // Čakaj na potvrdenie od klienta
                    nlohmann::json ack;
                    if (!recv_json(sock, ack)) {
                        std::cout << "[error] " << client_port << " client disconnected during download.\n";
                        break;
                    }

                    if (ack.value("status", "") != "OK" || ack.value("ack", -1) != (int)i) {
                        std::cout << "[error] " << client_port << " invalid ACK for chunk " << i << " — aborting download.\n";
                        break;
                    }

                    double progress = (file_size > 0)
                    ? (100.0 * static_cast<double>((i + 1) * CHUNK_SIZE > file_size ? file_size : (i + 1) * CHUNK_SIZE) / file_size)
                    : 0.0;

                    std::cout << "\r[info] sent chunk " << (i + 1) << "/" << total_chunks
                            << " (" << std::fixed << std::setprecision(1) << progress << "%)" << std::flush;
                }

                

                file.close();
                std::cout << "\n[ok] download finished successfully for " << path << " to client " << client_port << "\n";
            } else if (cmd == "UPLOAD") {
                std::string path = args.value("remote", "");
                std::string filename = fs::path(args.value("local", "")).filename().string();
                std::string path_with_filename = (fs::path(path) / filename).string();
                // std::cout << "[info] upload -> path: " << path << ", filename: " << filename << ", path_with_filename: " << path_with_filename << "\n";

                if (!is_path_under_root(root, path)) {
                    send_json(sock, {{"cmd","UPLOAD"},{"status","ERROR"},{"code",2},{"message","Access denied: path is outside root (" + root + ")"},{"data", "Access denied: path is outside root (" + root + ")"}});
                    std::cout << "[error] upload -> access denied, path: " << path << ", root: " << root << " local_path: " << args.value("local", "") << "\n";
                    continue;
                }

                if (fs::is_directory(path) && !fs::exists(path + "/" + filename)) {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "OK"}, {"message", "Ready to receive chunks"}});
                    std::cout << "[info] upload -> ready to receive chunks for '" << path << "'\n";
                } else {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "ERROR"}, {"message", "File already exists"}});
                    std::cout << "[error] upload -> reject upload to '" << path << "'\n";
                    continue;
                }

                if (fs::exists(path_with_filename)) {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "ERROR"}, {"message", "File already exists"}});
                    std::cout << "[error] upload -> file already exists at '" << path_with_filename << "'\n";
                    continue;
                }

                recv_json(sock, req);
                int64_t total_size = req.value("size", 0);  
                int64_t chunk_size = req.value("chunk_size", 0);
                int64_t total_chunks = req.value("total_chunks", 0);

                

                std::ofstream outfile(path_with_filename, std::ios::binary);
                if (!outfile.is_open()) {
                    send_json(sock, {{"cmd", "UPLOAD"}, {"status", "ERROR"}, {"message", "Cannot create file"}});
                    std::cout << "[error] upload -> cannot create file at '" << path << "'\n";
                    continue;
                }
                send_json(sock, {{"cmd", "UPLOAD"}, {"status", "OK"}, {"message", "Start sending chunks"}});
                std::cout << "[server] Starting upload file '" << path_with_filename << "' of size " << total_size << " bytes in " << total_chunks << " chunks. From client port: " << client_port << "\n";

                int err = 0;
                for (size_t i = 0; i < total_chunks; ++i) {
                    nlohmann::json chunk_header;
                    if (!recv_json(sock, chunk_header)) {
                        std::cout << "\n[error] " << client_port << " client disconnected during upload.\n";
                        err = 1;
                        break;
                    }

                    int64_t chunk_index = chunk_header.value("chunk_index", -1);
                    int64_t chunk_size = chunk_header.value("size", 0);
                    if (chunk_index != (int64_t)i || chunk_size <= 0) {
                        std::cout << "[error] " << client_port << " invalid chunk header for chunk " << i << " — aborting upload.\n";
                        err = 1;
                        break;
                    }

                    std::vector<char> buffer(chunk_size);
                    asio::read(sock, asio::buffer(buffer.data(), chunk_size));

                    outfile.write(buffer.data(), chunk_size);

                    // Posli ACK klientovi
                    send_json(sock, {{"status", "OK"}, {"ack", static_cast<int64_t>(i)}});

                    double progress = 100.0 * (double)(i + 1) / (double)total_chunks;
                    std::cout << "\r[info] received chunk " << (i + 1) << "/" << total_chunks
                            << " (" << std::fixed << std::setprecision(1) << progress << "%)" << std::flush;
                }

                outfile.close();
                if (!err) {
                    std::cout << "\n[ok] upload finished successfully for '" << path_with_filename << "' from client " << client_port << "\n";
                } else {
                    std::cout << "[error] upload failed for '" << path_with_filename << "' from client " << client_port << "\n";
                    std::error_code ec;
                    fs::remove(path_with_filename, ec);
                }

            } else {
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