// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProtocol.h"

#include <Lmcons.h>
#include <Windows.h>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <optional>
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

    [[nodiscard]] bool Boolean(bool& output)
    {
        SkipWhitespace();
        if (input_.substr(position_).starts_with("true"))
        {
            position_ += 4;
            output = true;
            return true;
        }
        if (input_.substr(position_).starts_with("false"))
        {
            position_ += 5;
            output = false;
            return true;
        }
        return false;
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

[[nodiscard]] bool ReadAccounts(JsonReader& reader, std::vector<std::wstring>& accounts)
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
        std::wstring account;
        if (!reader.String(account) || !IsValidProfileId(account) ||
            accounts.size() == MaximumArguments)
        {
            return false;
        }
        accounts.push_back(std::move(account));
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
    bool pipeResize = false;
    bool columns = false;
    bool rows = false;
    bool inheritCursorSeen = false;
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
        else if (name == L"pipeResize" && !pipeResize)
        {
            pipeResize = reader.String(console.pipeResize);
        }
        else if (name == L"inheritCursor" && !inheritCursorSeen)
        {
            inheritCursorSeen = reader.Boolean(console.inheritCursor);
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
        if (!(pipeIn || name != L"pipeIn") || !(pipeOut || name != L"pipeOut") ||
            !(pipeResize || name != L"pipeResize"))
        {
            return false;
        }
        if (reader.Consume('}'))
        {
            return pipeIn && pipeOut && pipeResize && columns && rows;
        }
        if (!reader.Consume(','))
        {
            return false;
        }
    }
}

template <typename ParseAdditionalField>
[[nodiscard]] bool ParseResponse(std::string_view response, std::wstring_view requestId,
    std::wstring_view expectedStatus, std::wstring_view expectedReason,
    std::optional<DWORD> expectedWin32Error, DWORD* parsedWin32Error,
    ParseAdditionalField&& parseAdditionalField)
{
    JsonReader reader(response);
    if (!reader.Consume('{'))
    {
        return false;
    }

    bool version = false;
    bool responseId = false;
    bool status = false;
    bool reason = false;
    bool error = false;
    for (;;)
    {
        std::wstring name;
        if (!reader.String(name) || !reader.Consume(':'))
        {
            return false;
        }
        if (name == L"version" && !version)
        {
            DWORD value = 0;
            version = reader.Unsigned(value) && value == 1;
        }
        else if (name == L"requestId" && !responseId)
        {
            std::wstring value;
            responseId = reader.String(value) && value == requestId;
        }
        else if (name == L"status" && !status)
        {
            std::wstring value;
            status = reader.String(value) && value == expectedStatus;
        }
        else if (name == L"reasonCode" && !reason)
        {
            std::wstring value;
            reason = reader.String(value) &&
                     (expectedReason.empty() ? !value.empty() : value == expectedReason);
        }
        else if (name == L"win32Error" && !error)
        {
            DWORD value = 0;
            error = reader.Unsigned(value) && (!expectedWin32Error || value == *expectedWin32Error);
            if (error && parsedWin32Error != nullptr)
            {
                *parsedWin32Error = value;
            }
        }
        else if (!parseAdditionalField(name, reader))
        {
            return false;
        }

        if (reader.Consume('}'))
        {
            return reader.End() && version && responseId && status && reason && error;
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

std::wstring_view RequestOperationName(RequestOperation operation) noexcept
{
    switch (operation)
    {
    case RequestOperation::ConsoleLaunch:
        return L"launch";
    case RequestOperation::Create:
        return L"create";
    case RequestOperation::TakeOver:
        return L"takeover";
    case RequestOperation::List:
        return L"list";
    case RequestOperation::Forget:
        return L"forget";
    case RequestOperation::Delete:
        return L"delete";
    }
    return L"unknown";
}

bool IsValidProfileId(std::wstring_view value) noexcept
{
    constexpr std::wstring_view invalidCharacters = L"\\/[]:;|=,+*?<>\"";
    return !value.empty() && value.size() <= UNLEN &&
           value.find_first_of(invalidCharacters) == std::wstring::npos &&
           std::all_of(
               value.begin(), value.end(), [](wchar_t character) { return character >= L' '; });
}

bool IsManagementOperation(RequestOperation operation) noexcept
{
    return operation != RequestOperation::ConsoleLaunch;
}

std::string_view RequestOperationSuccessReason(RequestOperation operation) noexcept
{
    switch (operation)
    {
    case RequestOperation::Create:
        return "created";
    case RequestOperation::TakeOver:
        return "taken_over";
    case RequestOperation::List:
        return "listed";
    case RequestOperation::Forget:
        return "forgotten";
    case RequestOperation::Delete:
        return "deleted";
    }
    return "unknown";
}

std::string_view RequestOperationFailureReason(RequestOperation operation) noexcept
{
    switch (operation)
    {
    case RequestOperation::Create:
        return "create_failed";
    case RequestOperation::TakeOver:
        return "takeover_failed";
    case RequestOperation::List:
        return "list_failed";
    case RequestOperation::Forget:
        return "forget_failed";
    case RequestOperation::Delete:
        return "delete_failed";
    }
    return "invalid_request";
}

std::string BuildManagementRequest(RequestOperation operation, std::wstring_view requestId,
    std::wstring_view profileId, bool confirmed, bool force)
{
    std::string request = "{\"version\":1,\"requestId\":";
    AppendJsonString(request, requestId);
    request += ",\"operation\":";
    AppendJsonString(request, RequestOperationName(operation));
    if (operation != RequestOperation::List)
    {
        request += ",\"profileId\":";
        AppendJsonString(request, profileId);
    }
    if (operation != RequestOperation::List)
    {
        request += confirmed ? ",\"confirmed\":true" : ",\"confirmed\":false";
    }
    if (force)
    {
        request += ",\"force\":true";
    }
    request += '}';
    return request;
}

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
        return ParseResult::InvalidRequest;
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
    bool modeSeen = false;
    enum class LaunchMode
    {
        Missing,
        Console,
        Interactive,
        Unknown
    };
    LaunchMode launchMode = LaunchMode::Missing;
    bool arguments = false;
    bool argumentsSeen = false;
    bool workingDirectory = false;
    bool workingDirectorySeen = false;
    bool console = false;
    bool consoleSeen = false;
    bool confirmed = false;
    bool confirmedSeen = false;
    bool forceSeen = false;
    for (;;)
    {
        std::wstring name;
        if (!reader.String(name) || !reader.Consume(':'))
        {
            return ParseResult::InvalidRequest;
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
            profile = reader.String(request.profileId) && IsValidProfileId(request.profileId);
        }
        else if (name == L"mode" && !modeSeen)
        {
            modeSeen = true;
            std::wstring value;
            if (!reader.String(value))
            {
                launchMode = LaunchMode::Unknown;
            }
            else if (value == L"console")
            {
                launchMode = LaunchMode::Console;
            }
            else if (value == L"interactive")
            {
                launchMode = LaunchMode::Interactive;
            }
            else
            {
                launchMode = LaunchMode::Unknown;
            }
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
        else if (name == L"confirmed" && !confirmedSeen)
        {
            confirmedSeen = true;
            confirmed = reader.Boolean(request.confirmed);
        }
        else if (name == L"force" && !forceSeen)
        {
            forceSeen = true;
            if (!reader.Boolean(request.force))
            {
                return ParseResult::InvalidRequest;
            }
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
            return ParseResult::InvalidRequest;
        }
    }
    if (!reader.End())
    {
        return ParseResult::InvalidRequest;
    }
    if (!version || !requestId || !operation || !IsRequestId(request.requestId))
    {
        return ParseResult::InvalidRequest;
    }
    if (operationName == L"list")
    {
        if (profileSeen || modeSeen || argumentsSeen || workingDirectorySeen || consoleSeen ||
            confirmedSeen || forceSeen)
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = RequestOperation::List;
        return ParseResult::Success;
    }
    if (!profile)
    {
        return ParseResult::InvalidRequest;
    }
    if (operationName == L"create")
    {
        if (modeSeen || argumentsSeen || workingDirectorySeen || consoleSeen || !confirmedSeen ||
            !confirmed)
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = RequestOperation::Create;
        return ParseResult::Success;
    }
    if (operationName == L"takeover" || operationName == L"forget" || operationName == L"delete")
    {
        if (modeSeen || argumentsSeen || workingDirectorySeen || consoleSeen || !confirmedSeen ||
            !confirmed)
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = operationName == L"takeover" ? RequestOperation::TakeOver
                            : operationName == L"forget" ? RequestOperation::Forget
                            : operationName == L"delete" ? RequestOperation::Delete
                                                         : RequestOperation::ConsoleLaunch;
        return ParseResult::Success;
    }
    if (forceSeen)
    {
        return ParseResult::InvalidRequest;
    }
    if (operationName != L"launch")
    {
        return ParseResult::InvalidRequest;
    }
    if (launchMode == LaunchMode::Interactive)
    {
        if (!arguments || !workingDirectory || consoleSeen)
        {
            return ParseResult::InvalidRequest;
        }
        return ParseResult::ModeNotSupported;
    }
    if (launchMode != LaunchMode::Console || !arguments || !workingDirectory || !console ||
        !IsConsolePipeName(request.console.pipeIn) || !IsConsolePipeName(request.console.pipeOut) ||
        !IsConsolePipeName(request.console.pipeResize) ||
        request.console.pipeIn == request.console.pipeOut ||
        request.console.pipeIn == request.console.pipeResize ||
        request.console.pipeOut == request.console.pipeResize)
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

std::string BuildListResponse(std::wstring_view requestId, std::span<const std::wstring> accounts)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"ok\",\"accounts\":[";
    for (std::size_t index = 0; index < accounts.size(); ++index)
    {
        if (index != 0)
        {
            response += ',';
        }
        AppendJsonString(response, accounts[index]);
    }
    response += "],\"reasonCode\":\"listed\",\"win32Error\":0}";
    return response;
}

bool ParseListResponse(
    std::string_view response, std::wstring_view requestId, std::vector<std::wstring>& accounts)
{
    accounts.clear();
    bool listedAccounts = false;
    const bool parsed = ParseResponse(response,
        requestId,
        L"ok",
        L"listed",
        ERROR_SUCCESS,
        nullptr,
        [&accounts, &listedAccounts](std::wstring_view name, JsonReader& reader)
        {
            if (name != L"accounts" || listedAccounts)
            {
                return false;
            }
            listedAccounts = ReadAccounts(reader, accounts);
            return listedAccounts;
        });
    if (!parsed || !listedAccounts)
    {
        accounts.clear();
        return false;
    }
    return true;
}

bool ParseErrorResponse(std::string_view response, std::wstring_view requestId, DWORD& win32Error)
{
    win32Error = ERROR_INVALID_DATA;
    if (!ParseResponse(response,
            requestId,
            L"error",
            {},
            std::nullopt,
            &win32Error,
            [](std::wstring_view, JsonReader&) { return false; }))
    {
        win32Error = ERROR_INVALID_DATA;
        return false;
    }
    return true;
}

std::string BuildLaunchSuccessResponse(std::wstring_view requestId, DWORD processId)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"ok\",\"processId\":" + std::to_string(processId);
    response += ",\"reasonCode\":\"launched\",\"win32Error\":0}";
    return response;
}

bool ParseLaunchSuccessResponse(
    std::string_view response, std::wstring_view requestId, DWORD& processId)
{
    processId = 0;
    bool process = false;
    const bool parsed = ParseResponse(response,
        requestId,
        L"ok",
        L"launched",
        ERROR_SUCCESS,
        nullptr,
        [&processId, &process](std::wstring_view name, JsonReader& reader)
        {
            if (name != L"processId" || process)
            {
                return false;
            }
            process = reader.Unsigned(processId) && processId != 0;
            return process;
        });
    if (!parsed || !process)
    {
        processId = 0;
        return false;
    }
    return true;
}

std::string BuildLaunchExitResponse(std::wstring_view requestId, DWORD exitCode)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"ok\",\"exitCode\":" + std::to_string(exitCode);
    response += ",\"reasonCode\":\"exited\",\"win32Error\":0}";
    return response;
}

bool ParseLaunchExitResponse(
    std::string_view response, std::wstring_view requestId, DWORD& exitCode)
{
    exitCode = 0;
    bool exit = false;
    const bool parsed = ParseResponse(response,
        requestId,
        L"ok",
        L"exited",
        ERROR_SUCCESS,
        nullptr,
        [&exitCode, &exit](std::wstring_view name, JsonReader& reader)
        {
            if (name != L"exitCode" || exit)
            {
                return false;
            }
            exit = reader.Unsigned(exitCode);
            return exit;
        });
    if (!parsed || !exit)
    {
        exitCode = 0;
        return false;
    }
    return true;
}

std::string BuildLaunchHostFailureResponse(
    std::wstring_view requestId, DWORD hostExitCode, std::wstring_view diagnostics)
{
    std::string response = "{\"version\":1,\"requestId\":";
    AppendJsonString(response, requestId);
    response += ",\"status\":\"error\",\"hostExitCode\":" + std::to_string(hostExitCode);
    response += ",\"diagnostic\":";
    AppendJsonString(response, diagnostics);
    response +=
        ",\"reasonCode\":\"host_failed\",\"win32Error\":" + std::to_string(ERROR_GEN_FAILURE) + "}";
    return response;
}

bool ParseLaunchHostFailureResponse(std::string_view response, std::wstring_view requestId,
    DWORD& hostExitCode, std::wstring& diagnostics)
{
    hostExitCode = 0;
    diagnostics.clear();
    bool hostExit = false;
    bool diagnostic = false;
    const bool parsed = ParseResponse(response,
        requestId,
        L"error",
        L"host_failed",
        ERROR_GEN_FAILURE,
        nullptr,
        [&hostExitCode, &hostExit, &diagnostics, &diagnostic](
            std::wstring_view name, JsonReader& reader)
        {
            if (name == L"hostExitCode" && !hostExit)
            {
                hostExit = reader.Unsigned(hostExitCode);
                return hostExit;
            }
            if (name == L"diagnostic" && !diagnostic)
            {
                diagnostic = reader.String(diagnostics);
                return diagnostic;
            }
            return false;
        });
    if (!parsed || !hostExit || !diagnostic)
    {
        hostExitCode = 0;
        diagnostics.clear();
        return false;
    }
    return true;
}

} // namespace launch_as::broker
