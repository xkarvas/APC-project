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
    std::cout << "[server] <- " << payload << "\n";
    out = nlohmann::json::parse(payload);
    return true;
}
static void send_json(tcp::socket& s, const nlohmann::json& j) {
    const std::string payload = j.dump();
    unsigned char hdr[4];
    write_u32_be(static_cast<uint32_t>(payload.size()), hdr);
    asio::write(s, asio::buffer(hdr, 4));
    asio::write(s, asio::buffer(payload.data(), payload.size()));
    std::cout << "[server] -> " << payload << "\n";
}

static void handle_client(tcp::socket sock) {
    try {
        std::cout << "[server] client connected from " << sock.remote_endpoint() << "\n";
        while (true) {
            nlohmann::json req;
            if (!recv_json(sock, req)) break;

            const std::string cmd = req.value("cmd", "");
            const auto args = req.value("args", nlohmann::json::object());
            std::cout << "[server] cmd=" << cmd << " args=" << args.dump() << "\n";

            // STUB odpoveď pre všetky podporované príkazy
            static const char* supported[] = {
                "LIST","MKDIR","RMDIR","DELETE","CD","MOVE","COPY",
                "UPLOAD","DOWNLOAD","SYNC","AUTH","REGISTER"
            };
            bool known = false;
            for (auto* c : supported) if (cmd == c) { known = true; break; }

            if (known) {
                nlohmann::json resp = {
                    {"status","OK"}, {"code",0}, {"message","stub"},
                    {"data", { {"echo_cmd",cmd}, {"echo_args",args} }}
                };
                send_json(sock, resp);
            } else {
                nlohmann::json resp = {{"status","ERROR"},{"code",1},{"message","Unknown cmd"}};
                send_json(sock, resp);
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