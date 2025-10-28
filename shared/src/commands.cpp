#include "minidrive/commands.hpp"
#include <algorithm>
#include <cctype>

namespace minidrive
{
    static std::vector<std::string> tokenize(const std::string &s)
    {
        std::vector<std::string> out;
        std::string cur;
        bool q = false;
        for (char c : s)
        {
            if (c == '"')
            {
                q = !q;
                continue;
            }
            if (std::isspace((unsigned char)c) && !q)
            {
                if (!cur.empty())
                {
                    out.push_back(cur);
                    cur.clear();
                }
            }
            else
                cur.push_back(c);
        }
        if (!cur.empty())
            out.push_back(cur);
        return out;
    }
    CommandType command_from_string(std::string_view sv)
    {
        std::string s(sv);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); }); // ked je malym daj na velke
        if (s == "LIST")
            return CommandType::LIST;
        if (s == "UPLOAD")
            return CommandType::UPLOAD;
        if (s == "DOWNLOAD")
            return CommandType::DOWNLOAD;
        if (s == "DELETE")
            return CommandType::DELETE_CMD;
        if (s == "CD")
            return CommandType::CD;
        if (s == "MKDIR")
            return CommandType::MKDIR;
        if (s == "RMDIR")
            return CommandType::RMDIR;
        if (s == "MOVE")
            return CommandType::MOVE;
        if (s == "COPY")
            return CommandType::COPY;
        if (s == "SYNC")
            return CommandType::SYNC;
        if (s == "EXIT")
            return CommandType::EXIT;
        if (s == "HELP" || s == "?")
            return CommandType::HELP;
        return CommandType::INVALID;
    }
    const char *to_string(CommandType t)
    {
        switch (t)
        {
        case CommandType::LIST:
            return "LIST";
        case CommandType::UPLOAD:
            return "UPLOAD";
        case CommandType::DOWNLOAD:
            return "DOWNLOAD";
        case CommandType::DELETE_CMD:
            return "DELETE";
        case CommandType::CD:
            return "CD";
        case CommandType::MKDIR:
            return "MKDIR";
        case CommandType::RMDIR:
            return "RMDIR";
        case CommandType::MOVE:
            return "MOVE";
        case CommandType::COPY:
            return "COPY";
        case CommandType::SYNC:
            return "SYNC";
        case CommandType::EXIT:
            return "EXIT";
        case CommandType::HELP:
            return "HELP";
        default:
            return "INVALID";
        }
    }
    ParsedCommand parse_line(const std::string &line)
    {
        ParsedCommand pc;
        auto t = tokenize(line);
        if (t.empty())
            return pc;
        pc.type = command_from_string(t.front());
        t.erase(t.begin());
        pc.args = std::move(t);
        return pc;
    }
    std::string help_text()
    {
        return "Commands:\n  LIST [path]\n  UPLOAD <local> [remote]\n  DOWNLOAD <remote> [local]\n"
               "  DELETE <path>\n  CD <path>\n  MKDIR <path>\n  RMDIR <path>\n  MOVE <src> <dst>\n"
               "  COPY <src> <dst>\n  SYNC <local> <remote>\n  HELP\n  EXIT\n";
    }
}