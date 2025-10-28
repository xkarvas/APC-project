#pragma once
#include <asio.hpp>
#include <string>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace minidrive {

class Session : public std::enable_shared_from_this<Session> {
public:
  Session(asio::ip::tcp::socket socket, std::filesystem::path root);
  void start();

private:
  void do_read();
  void on_read(std::error_code ec, std::size_t n);
  void handle_one_message(const nlohmann::json& req);
  void send_json(const nlohmann::json& resp);

  asio::ip::tcp::socket socket_;
  std::string inbuf_;
  std::filesystem::path root_;
  std::filesystem::path cwd_;
};

} 