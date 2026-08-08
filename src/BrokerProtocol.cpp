// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProtocol.h"

#include <Windows.h>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace launch_as::broker
{
namespace
{

class JsonReader final
{
  public:
    explicit JsonReader(std::string_view input) noexcept : input_(input) {}

    [[nodiscard]] bool End()
    {
        SkipWhitespace();
        return position_ == input_.size();
    }

    [[nodiscard]] bool Consume(char expected)
    {
        SkipWhitespace();
        if (position_ == input_.size() || input_[position_] != expected)
        {
            return false;
        }
        ++position_;
        return true;
    }

    [[nodiscard]] bool String(std::wstring& output)
    {
        SkipWhitespace();
        if (position_ == input_.size() || input_[position_++] != '"')
        {
            return false;
        }

        std::string utf8;
        while (position_ < input_.size())
        {
            const char character = input_[position_++];
            if (character == '"')
            {
                return Utf8ToWide(utf8, output);
            }
            if (static_cast<unsigned char>(character) < 0x20)
            {
                return false;
            }
            if (character != '\\')
            {
                utf8.push_back(character);
                continue;
            }
            if (position_ == input_.size())
            {
                return false;
            }
            switch (input_[position_++])
            {
            case '"':
            case '\\':
            case '/':
                utf8.push_back(input_[position_ - 1]);
                break;
            case 'b':
                utf8.push_back('\b');
                break;
            case 'f':
                utf8.push_back('\f');
                break;
            case 'n':
                utf8.push_back('\n');
                break;
            case 'r':
                utf8.push_back('\r');
                break;
            case 't':
                utf8.push_back('\t');
                break;
            case 'u':
                if (!UnicodeEscape(utf8))
                {
                    return false;
                }
                break;
            default:
                return false;
            }
        }
        return false;
    }

    [[nodiscard]] bool Unsigned(DWORD& output)
    {
        SkipWhitespace();
        const std::size_t start = position_;
        while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
        {
            ++position_;
        }
        if (start == position_)
        {
            return false;
        }
        unsigned long value = 0;
        const auto [end, error] =
            std::from_chars(input_.data() + start, input_.data() + position_, value);
        if (error != std::errc {} || end != input_.data() + position_ ||
            value > std::numeric_limits<DWORD>::max())
        {
            return false;
        }
        output = static_cast<DWORD>(value);
        return true;
    }

  private:
    void SkipWhitespace() noexcept
    {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\n' ||
                   input_[position_] == '\r' || input_[position_] == '\t'))
        {
            ++position_;
        }
    }

    [[nodiscard]] bool UnicodeEscape(std::string& output)
    {
        unsigned int value = 0;
        if (!ReadUnicodeEscape(value))
        {
            return false;
        }
        if (value >= 0xD800 && value <= 0xDBFF)
        {
            if (position_ + 2 > input_.size() || input_[position_++] != '\\' ||
                input_[position_++] != 'u')
            {
                return false;
            }
            unsigned int lowSurrogate = 0;
            if (!ReadUnicodeEscape(lowSurrogate) || lowSurrogate < 0xDC00 || lowSurrogate > 0xDFFF)
            {
                return false;
            }
            value = 0x10000 + ((value - 0xD800) << 10) + (lowSurrogate - 0xDC00);
        }
        else if (value >= 0xDC00 && value <= 0xDFFF)
        {
            return false;
        }
        AppendUtf8(value, output);
        return true;
    }

    [[nodiscard]] bool ReadUnicodeEscape(unsigned int& value)
    {
        if (position_ + 4 > input_.size())
        {
            return false;
        }
        value = 0;
        for (std::size_t index = 0; index < 4; ++index)
        {
            const char character = input_[position_++];
            value <<= 4;
            if (character >= '0' && character <= '9')
            {
                value |= static_cast<unsigned int>(character - '0');
            }
            else if (character >= 'a' && character <= 'f')
            {
                value |= static_cast<unsigned int>(character - 'a' + 10);
            }
            else if (character >= 'A' && character <= 'F')
            {
                value |= static_cast<unsigned int>(character - 'A' + 10);
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    static void AppendUtf8(unsigned int codePoint, std::string& output)
    {
        if (codePoint < 0x80)
        {
            output.push_back(static_cast<char>(codePoint));
        }
        else if (codePoint < 0x800)
        {
            output.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint < 0x10000)
        {
            output.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else
        {
            output.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }

    static bool Utf8ToWide(const std::string& input, std::wstring& output)
    {
        if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            return false;
        }
        const int length = MultiByteToWideChar(CP_UTF8,
            MB_ERR_INVALID_CHARS,
            input.data(),
            static_cast<int>(input.size()),
            nullptr,
            0);
        if (length == 0 && !input.empty())
        {
            return false;
        }
        output.resize(static_cast<std::size_t>(length));
        return length == 0 || MultiByteToWideChar(CP_UTF8,
                                  MB_ERR_INVALID_CHARS,
                                  input.data(),
                                  static_cast<int>(input.size()),
                                  output.data(),
                                  length) == length;
    }

    std::string_view input_;
    std::size_t position_ = 0;
};

[[nodiscard]] bool IsRequestId(const std::wstring& value)
{
    if (value.size() != 36)
    {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index)
    {
        if (index == 8 || index == 13 || index == 18 || index == 23)
        {
            if (value[index] != L'-')
            {
                return false;
            }
            continue;
        }
        if (!((value[index] >= L'0' && value[index] <= L'9') ||
                (value[index] >= L'a' && value[index] <= L'f') ||
                (value[index] >= L'A' && value[index] <= L'F')))
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool IsConsolePipeName(const std::wstring& value)
{
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\launch-as-";
    return value.size() > prefix.size() && value.starts_with(prefix) && value.size() <= 256 &&
           value.find_first_of(L"\\/", prefix.size()) == std::wstring::npos;
}

[[nodiscard]] bool ReadArguments(JsonReader& reader, std::vector<std::wstring>& arguments)
{
    if (!reader.Consume('['))
    {
        return false;
    }
    if (reader.Consume(']'))
    {
        return true;
    }
    for (;;)
    {
        std::wstring argument;
        if (!reader.String(argument) || argument.size() > 8 * 1024 ||
            arguments.size() == MaximumArguments)
        {
            return false;
        }
        arguments.push_back(std::move(argument));
        if (reader.Consume(']'))
        {
            return true;
        }
        if (!reader.Consume(','))
        {
            return false;
        }
    }
}

[[nodiscard]] bool ReadConsole(JsonReader& reader, ConsoleRequest& console)
{
    if (!reader.Consume('{'))
    {
        return false;
    }
    bool pipeIn = false;
    bool pipeOut = false;
    bool columns = false;
    bool rows = false;
    for (;;)
    {
        std::wstring name;
        if (!reader.String(name) || !reader.Consume(':'))
        {
            return false;
        }
        if (name == L"pipeIn" && !pipeIn)
        {
            pipeIn = reader.String(console.pipeIn);
        }
        else if (name == L"pipeOut" && !pipeOut)
        {
            pipeOut = reader.String(console.pipeOut);
        }
        else
        {
            DWORD value = 0;
            if ((name == L"cols" && !columns) || (name == L"rows" && !rows))
            {
                if (!reader.Unsigned(value) || value == 0 ||
                    value > static_cast<DWORD>(std::numeric_limits<SHORT>::max()))
                {
                    return false;
                }
                if (name == L"cols")
                {
                    console.columns = static_cast<SHORT>(value);
                    columns = true;
                }
                else
                {
                    console.rows = static_cast<SHORT>(value);
                    rows = true;
                }
            }
            else
            {
                return false;
            }
        }
        if (!(pipeIn || name != L"pipeIn") || !(pipeOut || name != L"pipeOut"))
        {
            return false;
        }
        if (reader.Consume('}'))
        {
            return pipeIn && pipeOut && columns && rows;
        }
        if (!reader.Consume(','))
        {
            return false;
        }
    }
}

void AppendJsonString(std::string& output, std::wstring_view value)
{
    output.push_back('"');
    for (const wchar_t character : value)
    {
        if (character == L'"' || character == L'\\')
        {
            output.push_back('\\');
            output.push_back(static_cast<char>(character));
        }
        else if (character >= 0x20 && character <= 0x7E)
        {
            output.push_back(static_cast<char>(character));
        }
        else
        {
            constexpr char hexadecimal[] = "0123456789ABCDEF";
            output += "\\u";
            output.push_back(hexadecimal[(character >> 12) & 0xF]);
            output.push_back(hexadecimal[(character >> 8) & 0xF]);
            output.push_back(hexadecimal[(character >> 4) & 0xF]);
            output.push_back(hexadecimal[character & 0xF]);
        }
    }
    output.push_back('"');
}

} // namespace

ParseResult ParseBrokerRequest(std::string_view message, BrokerRequest& request)
{
    request = {};
    if (message.empty() || message.size() > MaximumMessageBytes)
    {
        return ParseResult::InvalidRequest;
    }

    JsonReader reader(message);
    if (!reader.Consume('{'))
    {
        return ParseResult::InvalidJson;
    }

    bool version = false;
    bool versionSeen = false;
    bool requestId = false;
    bool requestIdSeen = false;
    bool operation = false;
    bool operationSeen = false;
    std::wstring operationName;
    bool profile = false;
    bool profileSeen = false;
    bool mode = false;
    bool modeSeen = false;
    bool arguments = false;
    bool argumentsSeen = false;
    bool workingDirectory = false;
    bool workingDirectorySeen = false;
    bool console = false;
    bool consoleSeen = false;
    for (;;)
    {
        std::wstring name;
        if (!reader.String(name) || !reader.Consume(':'))
        {
            return ParseResult::InvalidJson;
        }
        if (name == L"version" && !versionSeen)
        {
            versionSeen = true;
            DWORD value = 0;
            version = reader.Unsigned(value) && value == 1;
        }
        else if (name == L"requestId" && !requestIdSeen)
        {
            requestIdSeen = true;
            requestId = reader.String(request.requestId);
        }
        else if (name == L"operation" && !operationSeen)
        {
            operationSeen = true;
            operation = reader.String(operationName);
        }
        else if (name == L"profileId" && !profileSeen)
        {
            profileSeen = true;
            std::wstring value;
            profile = reader.String(value) && value == L"agent-sandbox";
        }
        else if (name == L"mode" && !modeSeen)
        {
            modeSeen = true;
            std::wstring value;
            mode = reader.String(value) && value == L"console";
        }
        else if (name == L"arguments" && !argumentsSeen)
        {
            argumentsSeen = true;
            arguments = ReadArguments(reader, request.arguments);
        }
        else if (name == L"workingDirectory" && !workingDirectorySeen)
        {
            workingDirectorySeen = true;
            workingDirectory = reader.String(request.workingDirectory) &&
                               !request.workingDirectory.empty() &&
                               request.workingDirectory.size() <= 32 * 1024;
        }
        else if (name == L"console" && !consoleSeen)
        {
            consoleSeen = true;
            console = ReadConsole(reader, request.console);
        }
        else
        {
            return ParseResult::InvalidRequest;
        }
        if (reader.Consume('}'))
        {
            break;
        }
        if (!reader.Consume(','))
        {
            return ParseResult::InvalidJson;
        }
    }
    if (!reader.End())
    {
        return ParseResult::InvalidJson;
    }
    if (!version || !requestId || !operation || !profile || !IsRequestId(request.requestId))
    {
        return ParseResult::InvalidRequest;
    }
    if (operationName == L"register")
    {
        if (modeSeen || argumentsSeen || workingDirectorySeen || consoleSeen)
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = RequestOperation::Register;
        return ParseResult::Success;
    }
    if (operationName != L"launch" || !mode || !arguments || !workingDirectory || !console ||
        !IsConsolePipeName(request.console.pipeIn) || !IsConsolePipeName(request.console.pipeOut) ||
        request.console.pipeIn == request.console.pipeOut)
    {
        return ParseResult::InvalidRequest;
    }
    request.operation = RequestOperation::ConsoleLaunch;
    return ParseResult::Success;
}

std::string BuildErrorResponse(
    std::wstring_view requestId, std::string_view reasonCode, DWORD win32Error)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"error\",\"reasonCode\":\"";
    response.append(reasonCode);
    response += "\",\"win32Error\":" + std::to_string(win32Error) + "}";
    return response;
}

std::string BuildSuccessResponse(std::wstring_view requestId, std::string_view reasonCode)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"ok\",\"reasonCode\":\"";
    response.append(reasonCode);
    response += "\",\"win32Error\":0}";
    return response;
}

std::string BuildLaunchSuccessResponse(std::wstring_view requestId, DWORD processId)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"ok\",\"processId\":" + std::to_string(processId);
    response += ",\"reasonCode\":\"launched\",\"win32Error\":0}";
    return response;
}

} // namespace launch_as::broker
