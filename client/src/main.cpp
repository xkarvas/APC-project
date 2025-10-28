#include <iostream>
#include <string>
#include "minidrive/version.hpp"
#include "minidrive/commands.hpp"
#include "connection.hpp"

using minidrive::ParsedCommand;
using minidrive::CommandType;

static std::unique_ptr<minidrive::Connection> g_conn;


namespace {

// Pomocná funkcia pre jednotný výpis chýb
void print_usage_error(const std::string& cmd, const std::string& usage) {
  std::cout << "❌  Invalid usage of '" << cmd << "'. Correct syntax:\n"
            << "    " << usage << "\n";
}


void ensure_connection() {
  if (!g_conn) {
    g_conn = std::make_unique<minidrive::Connection>();
    // host/port napevno; neskôr z argv
    g_conn->connect("127.0.0.1", "5050");
  }
}



// ================= HANDLERY =================
void handle_list(const std::vector<std::string>& args) {
  ensure_connection();
  std::string path = args.empty() ? "." : args[0];
  nlohmann::json req = {{"cmd","LIST"}, {"args", {{"path", path}}}};
  auto resp = g_conn->request(req);
  if (resp.value("status","ERROR") == "OK") {
    for (auto& e : resp["data"]["entries"]) {
      std::cout << (e["type"]=="dir" ? "[DIR]  " : "      ")
                << e["name"].get<std::string>();
      if (e["type"]=="file") std::cout << "  (" << e["size"].get<long long>() << " B)";
      std::cout << "\n";
    }
  } else {
    std::cout << "ERROR " << resp.value("code", -1) << ": "
              << resp.value("message", "") << "\n";
  }
}

void handle_upload(const std::vector<std::string>& args) {
  if (args.empty()) {
    print_usage_error("UPLOAD", "UPLOAD <local> [remote]");
    return;
  }
  std::string local = args[0];
  std::string remote = (args.size() >= 2) ? args[1] : args[0];

  std::cout << "⬆️  Uploading '" << local << "' → '" << remote << "'\n";
}

void handle_download(const std::vector<std::string>& args) {
  if (args.empty()) {
    print_usage_error("DOWNLOAD", "DOWNLOAD <remote> [local]");
    return;
  }
  std::string remote = args[0];
  std::string local = (args.size() >= 2) ? args[1] : args[0];

  std::cout << "⬇️  Downloading '" << remote << "' → '" << local << "'\n";
}

void handle_delete(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    print_usage_error("DELETE", "DELETE <path>");
    return;
  }
  std::cout << "🗑️  Deleting '" << args[0] << "'\n";
}

void handle_cd(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    print_usage_error("CD", "CD <path>");
    return;
  }
  std::cout << "📂 Changing directory to '" << args[0] << "'\n";
}

void handle_mkdir(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    print_usage_error("MKDIR", "MKDIR <path>");
    return;
  }
  std::cout << "📁 Creating directory '" << args[0] << "'\n";
}

void handle_rmdir(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    print_usage_error("RMDIR", "RMDIR <path>");
    return;
  }
  std::cout << "🗑️  Removing directory '" << args[0] << "'\n";
}

void handle_move(const std::vector<std::string>& args) {
  if (args.size() != 2) {
    print_usage_error("MOVE", "MOVE <src> <dst>");
    return;
  }
  std::cout << "🚚 Moving '" << args[0] << "' → '" << args[1] << "'\n";
}

void handle_copy(const std::vector<std::string>& args) {
  if (args.size() != 2) {
    print_usage_error("COPY", "COPY <src> <dst>");
    return;
  }
  std::cout << "📄 Copying '" << args[0] << "' → '" << args[1] << "'\n";
}

void handle_sync(const std::vector<std::string>& args) {
  if (args.size() != 2) {
    print_usage_error("SYNC", "SYNC <local_dir> <remote_dir>");
    return;
  }
  std::cout << "🔄 Syncing local='" << args[0] << "' with remote='" << args[1] << "'\n";
}

} // namespace


// ================= MAIN =================
int main(int argc, char* argv[]) {
  std::cout << "MiniDrive client (version " << minidrive::version() << ")\n";
  std::cout << "Type HELP for a list of commands.\n";

  std::string line;
  while (true) {
    std::cout << "> ";
    if (!std::getline(std::cin, line)) break;

    ParsedCommand pc = minidrive::parse_line(line);

    switch (pc.type) {
      case CommandType::LIST:      handle_list(pc.args); break;
      case CommandType::UPLOAD:    handle_upload(pc.args); break;
      case CommandType::DOWNLOAD:  handle_download(pc.args); break;
      case CommandType::DELETE_CMD:handle_delete(pc.args); break;
      case CommandType::CD:        handle_cd(pc.args); break;
      case CommandType::MKDIR:     handle_mkdir(pc.args); break;
      case CommandType::RMDIR:     handle_rmdir(pc.args); break;
      case CommandType::MOVE:      handle_move(pc.args); break;
      case CommandType::COPY:      handle_copy(pc.args); break;
      case CommandType::SYNC:      handle_sync(pc.args); break;
      case CommandType::HELP:
        std::cout << minidrive::help_text();
        break;
      case CommandType::EXIT:
        std::cout << "👋 Bye!\n";
        return 0;
      default:
        if (!line.empty()) {
          std::cout << "⚠️  Unknown command. Type HELP.\n";
        }
        break;
    }
  }

  return 0;
}