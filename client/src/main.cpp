#include <iostream>
#include <string>
#include "minidrive/version.hpp"
#include "minidrive/commands.hpp"

using minidrive::ParsedCommand;
using minidrive::CommandType;

namespace {

// Pomocná funkcia pre jednotný výpis chýb
void print_usage_error(const std::string& cmd, const std::string& usage) {
  std::cout << "❌  Invalid usage of '" << cmd << "'. Correct syntax:\n"
            << "    " << usage << "\n";
}

// ================= HANDLERY =================
void handle_list(const std::vector<std::string>& args) {
  if (args.size() > 1) {
    print_usage_error("LIST", "LIST [path]");
    return;
  }
  std::cout << "📁 Listing files";
  if (!args.empty()) std::cout << " in path: " << args[0];
  std::cout << "\n";
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
  std::cout << "MiniDrive client (version " << minidrive::version << ")\n";
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