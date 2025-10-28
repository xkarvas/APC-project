#pragma once
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <string>

namespace minidrive {

class Connection {
public:
  void connect(const std::string& host, const std::string& port);
  nlohmann::json request(const nlohmann::json& req);

private:
  asio::io_context io_;
  asio::ip::tcp::socket sock_{io_};
};

} // namespace minidrive