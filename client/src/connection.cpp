#include "connection.hpp"
#include "minidrive/protocol.hpp"
#include <asio/connect.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>

namespace minidrive {

void Connection::connect(const std::string& host, const std::string& port) {
  asio::ip::tcp::resolver r(io_);
  auto res = r.resolve(host, port);
  asio::connect(sock_, res);
}

nlohmann::json Connection::request(const nlohmann::json& req) {
  auto bytes = frame_json(req);
  asio::write(sock_, asio::buffer(bytes));

  // načítaj najprv 4B dĺžku
  uint32_t be_len;
  asio::read(sock_, asio::buffer(&be_len, 4));
  uint32_t len = ntohl(be_len);
  std::string payload(len, '\0');
  asio::read(sock_, asio::buffer(payload.data(), len));
  return nlohmann::json::parse(payload);
}

} // namespace minidrive