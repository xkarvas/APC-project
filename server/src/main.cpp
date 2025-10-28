#include <asio.hpp>
#include <iostream>
#include <filesystem>
#include "session.hpp"

int main(int argc, char* argv[]) {
  using asio::ip::tcp;
  int port = 5050;
  std::filesystem::path root = "/Users/ervinkarvas/Desktop/FIIT/APC/root";
  if (argc >= 2) port = std::stoi(argv[1]);
  if (argc >= 3) root = argv[2];

  asio::io_context io;
  tcp::acceptor acc(io, tcp::endpoint(tcp::v4(), port));
  std::cout << "Server listening on 0.0.0.0:" << port << "\nRoot: " << root << "\n";

  for (;;) {
    tcp::socket sock(io);
    acc.accept(sock); // blocking accept – začiatočnícky OK
    std::make_shared<minidrive::Session>(std::move(sock), root)->start();
    // (V base verzii obslúži jednu správu – neskôr spravíš cyklus čítania.)
  }
}