#include "session.hpp"
#include "minidrive/protocol.hpp"
#include <asio/read.hpp>
#include <asio/write.hpp>

namespace fs = std::filesystem;

namespace minidrive {

Session::Session(asio::ip::tcp::socket socket, fs::path root)
 : socket_(std::move(socket)), root_(fs::weakly_canonical(root)), cwd_(root_) {}

void Session::start() { do_read(); }

void Session::do_read() {
  auto self = shared_from_this();
  socket_.async_read_some(asio::buffer(inbuf_.data(), 0), // trik: nič nečítame, použijeme read_some do dočasného bufferu
                          [self](auto, auto){ /* no-op, použijeme dostupné bytes */ });
  // jednoduchšie: použijeme blocking read_until pre demo – začiatočnícky vhodné:
  // ale my máme rámovanie; urobíme radšej malý loop:
  asio::async_read(socket_, asio::buffer(inbuf_.data(), 0),
    [self](std::error_code, std::size_t){});
}

// Začiatočnícka verzia: použime blocking operácie (ľahšie na pochopenie)
// Urobíme jednu „iteráciu“: načítame rámec, spracujeme, odpovieme, potom zavoláme znova do_read().
void Session::on_read(std::error_code, std::size_t) { /* (nepoužité v tejto jednoduchej verzii) */ }

void Session::handle_one_message(const nlohmann::json& req) {
  nlohmann::json resp;
  std::string cmd = req.value("cmd", "");
  auto args = req.value("args", nlohmann::json::object());

  if (cmd == "LIST") {
    fs::path p = args.value("path", ".");
    fs::path abs = fs::weakly_canonical(root_ / p);
    if (abs.string().rfind(root_.string(), 0) != 0) {
      resp = {{"status","ERROR"},{"code",3},{"message","Path escapes root"}};
    } else if (!fs::exists(abs)) {
      resp = {{"status","ERROR"},{"code",2},{"message","Not found"}};
    } else {
      nlohmann::json entries = nlohmann::json::array();
      for (auto& e : fs::directory_iterator(abs)) {
        entries.push_back({
          {"name", e.path().filename().string()},
          {"type", e.is_directory() ? "dir" : "file"},
          {"size", e.is_directory() ? 0 : (long long)fs::file_size(e.path())}
        });
      }
      resp = {{"status","OK"},{"code",0},{"message",""},{"data", {{"entries", entries}}}};
    }
  } else {
    resp = {{"status","ERROR"},{"code",1},{"message","Unknown cmd"}};
  }
  send_json(resp);
}

void Session::send_json(const nlohmann::json& resp) {
  auto bytes = minidrive::frame_json(resp);
  asio::write(socket_, asio::buffer(bytes)); // jednoduchý blocking write
}

} // namespace minidrive