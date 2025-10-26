#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace minidrive {
enum class CommandType { LIST, UPLOAD, DOWNLOAD, DELETE_CMD, CD, MKDIR, RMDIR, MOVE, COPY, SYNC, EXIT, HELP, INVALID };
struct ParsedCommand { CommandType type{CommandType::INVALID}; std::vector<std::string> args; };

CommandType command_from_string(std::string_view);
const char* to_string(CommandType);
ParsedCommand parse_line(const std::string& line);
std::string help_text();
}