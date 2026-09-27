// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProtocol.h"

#include "Utf8.h"

#include <Lmcons.h>
#include <Windows.h>
#include <algorithm>
#include <array>
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
                return launch_as::Utf8ToWide(utf8, output);
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
        AppendUtf8CodePoint(value, output);
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

    static void AppendUtf8CodePoint(unsigned int codePoint, std::string& output)
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

[[nodiscard]] bool IsLogonSid(std::wstring_view value)
{
    constexpr std::wstring_view prefix = L"S-1-5-5-";
    if (!value.starts_with(prefix))
    {
        return false;
    }
    value.remove_prefix(prefix.size());
    const std::size_t separator = value.find(L'-');
    if (separator == std::wstring_view::npos || separator == 0 || separator + 1 == value.size() ||
        value.find(L'-', separator + 1) != std::wstring_view::npos)
    {
        return false;
    }
    const auto isDecimal = [](std::wstring_view component)
    {
        return std::all_of(component.begin(),
            component.end(),
            [](wchar_t character) { return character >= L'0' && character <= L'9'; });
    };
    return isDecimal(value.substr(0, separator)) && isDecimal(value.substr(separator + 1));
}

[[nodiscard]] std::wstring_view InteractiveLeaseOperationName(
    InteractiveLeaseOperation operation) noexcept
{
    return operation == InteractiveLeaseOperation::Acquire ? L"acquire" : L"release";
}

[[nodiscard]] bool IsConsolePipeName(const std::wstring& value)
{
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\launch-as-";
    return value.size() > prefix.size() && value.starts_with(prefix) && value.size() <= 256 &&
           value.find_first_of(L"\\/", prefix.size()) == std::wstring::npos;
}

// Reads a non-empty JSON object. readField consumes the value of each member and returns false to
// reject the object, including for an unknown or duplicate name.
template <typename ReadField>
[[nodiscard]] bool ReadObject(JsonReader& reader, ReadField&& readField)
{
    if (!reader.Consume('{'))
    {
        return false;
    }
    for (;;)
    {
        std::wstring name;
        if (!reader.String(name) || !reader.Consume(':') || !readField(name))
        {
            return false;
        }
        if (reader.Consume('}'))
        {
            return true;
        }
        if (!reader.Consume(','))
        {
            return false;
        }
    }
}

// Marks a field as seen; returns false when it was already seen.
[[nodiscard]] bool FirstSeen(bool& seen) noexcept { return !std::exchange(seen, true); }

template <typename IsValid>
[[nodiscard]] bool ReadStringArray(
    JsonReader& reader, std::vector<std::wstring>& values, IsValid&& isValid)
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
        std::wstring value;
        if (!reader.String(value) || !isValid(value) || values.size() == MaximumArguments)
        {
            return false;
        }
        values.push_back(std::move(value));
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
    bool pipeIn = false;
    bool pipeOut = false;
    bool pipeResize = false;
    bool inheritCursor = false;
    return ReadObject(reader,
               [&](std::wstring_view name)
               {
                   if (name == L"pipeIn")
                   {
                       return FirstSeen(pipeIn) && reader.String(console.pipeIn);
                   }
                   if (name == L"pipeOut")
                   {
                       return FirstSeen(pipeOut) && reader.String(console.pipeOut);
                   }
                   if (name == L"pipeResize")
                   {
                       return FirstSeen(pipeResize) && reader.String(console.pipeResize);
                   }
                   if (name == L"inheritCursor")
                   {
                       return FirstSeen(inheritCursor) && reader.Boolean(console.inheritCursor);
                   }
                   return false;
               }) &&
           pipeIn && pipeOut && pipeResize;
}

[[nodiscard]] bool ReadInteractiveLaunch(JsonReader& reader, InteractiveLaunchRequest& interactive)
{
    bool leasePipe = false;
    bool nonce = false;
    return ReadObject(reader,
               [&](std::wstring_view name)
               {
                   if (name == L"leasePipe")
                   {
                       return FirstSeen(leasePipe) && reader.String(interactive.leasePipe);
                   }
                   if (name == L"nonce")
                   {
                       return FirstSeen(nonce) && reader.String(interactive.nonce);
                   }
                   return false;
               }) &&
           leasePipe && nonce;
}

template <typename ParseAdditionalField>
[[nodiscard]] bool ParseResponse(std::string_view response, std::wstring_view requestId,
    std::wstring_view expectedStatus, std::wstring_view expectedReason,
    std::optional<DWORD> expectedWin32Error, DWORD* parsedWin32Error,
    ParseAdditionalField&& parseAdditionalField)
{
    JsonReader reader(response);
    bool version = false;
    bool responseId = false;
    bool status = false;
    bool reason = false;
    bool error = false;
    const bool parsed = ReadObject(reader,
        [&](std::wstring_view name)
        {
            DWORD number = 0;
            std::wstring text;
            if (name == L"version")
            {
                return FirstSeen(version) && reader.Unsigned(number) && number == 1;
            }
            if (name == L"requestId")
            {
                return FirstSeen(responseId) && reader.String(text) && text == requestId;
            }
            if (name == L"status")
            {
                return FirstSeen(status) && reader.String(text) && text == expectedStatus;
            }
            if (name == L"reasonCode")
            {
                return FirstSeen(reason) && reader.String(text) &&
                       (expectedReason.empty() ? !text.empty() : text == expectedReason);
            }
            if (name == L"win32Error")
            {
                if (!FirstSeen(error) || !reader.Unsigned(number) ||
                    (expectedWin32Error && number != *expectedWin32Error))
                {
                    return false;
                }
                if (parsedWin32Error != nullptr)
                {
                    *parsedWin32Error = number;
                }
                return true;
            }
            return parseAdditionalField(name, reader);
        });
    return parsed && reader.End() && version && responseId && status && reason && error;
}

} // namespace

bool IsInteractiveLeasePipeName(std::wstring_view value) noexcept
{
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\launch-as-interactive-";
    return value.size() > prefix.size() && value.starts_with(prefix) && value.size() <= 256 &&
           value.find_first_of(L"\\/", prefix.size()) == std::wstring_view::npos;
}

DWORD ReadPipeMessage(HANDLE pipe, std::string& message)
{
    std::array<char, MaximumMessageBytes> buffer {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr))
    {
        const DWORD readError = GetLastError();
        return readError;
    }
    if (bytesRead == 0)
    {
        return ERROR_BROKEN_PIPE;
    }
    message.assign(buffer.data(), bytesRead);
    return ERROR_SUCCESS;
}

DWORD WritePipeMessage(HANDLE pipe, std::string_view message)
{
    DWORD bytesWritten = 0;
    if (!WriteFile(
            pipe, message.data(), static_cast<DWORD>(message.size()), &bytesWritten, nullptr))
    {
        const DWORD writeError = GetLastError();
        return writeError;
    }
    return bytesWritten == message.size() ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
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

std::wstring_view RequestOperationName(RequestOperation operation) noexcept
{
    switch (operation)
    {
    case RequestOperation::ConsoleLaunch:
    case RequestOperation::InteractiveLaunch:
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
    return operation != RequestOperation::ConsoleLaunch &&
           operation != RequestOperation::InteractiveLaunch;
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
    std::wstring_view profileId, bool force)
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
    if (force)
    {
        request += ",\"force\":true";
    }
    request += '}';
    return request;
}

namespace
{

// Validates the fields shared by both launch modes and writes the request up to the mode block.
[[nodiscard]] bool BeginLaunchRequest(std::wstring_view requestId, std::wstring_view profileId,
    std::string_view mode, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, std::string& request)
{
    if (requestId.empty() || profileId.empty() || arguments.empty() || workingDirectory.empty() ||
        !IsValidUtf16(requestId) || !IsValidUtf16(profileId) || !IsValidUtf16(workingDirectory) ||
        !std::all_of(arguments.begin(),
            arguments.end(),
            [](const std::wstring& argument) { return IsValidUtf16(argument); }))
    {
        return false;
    }
    request = "{\"version\":1,\"requestId\":";
    AppendJsonString(request, requestId);
    request += ",\"operation\":\"launch\",\"profileId\":";
    AppendJsonString(request, profileId);
    request += ",\"mode\":\"";
    request += mode;
    request += "\",\"arguments\":[";
    for (std::size_t index = 0; index < arguments.size(); ++index)
    {
        if (index != 0)
        {
            request.push_back(',');
        }
        AppendJsonString(request, arguments[index]);
    }
    request += "],\"workingDirectory\":";
    AppendJsonString(request, workingDirectory);
    return true;
}

} // namespace

bool BuildConsoleLaunchRequest(std::wstring_view requestId, std::wstring_view profileId,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    std::wstring_view pipeIn, std::wstring_view pipeOut, std::wstring_view pipeResize,
    bool inheritCursor, std::string& request)
{
    if (pipeIn.empty() || pipeOut.empty() || pipeResize.empty() || !IsValidUtf16(pipeIn) ||
        !IsValidUtf16(pipeOut) || !IsValidUtf16(pipeResize) ||
        !BeginLaunchRequest(requestId, profileId, "console", arguments, workingDirectory, request))
    {
        return false;
    }
    request += ",\"console\":{\"pipeIn\":";
    AppendJsonString(request, pipeIn);
    request += ",\"pipeOut\":";
    AppendJsonString(request, pipeOut);
    request += ",\"pipeResize\":";
    AppendJsonString(request, pipeResize);
    request += ",\"inheritCursor\":";
    request += inheritCursor ? "true}}" : "false}}";
    return request.size() <= MaximumMessageBytes;
}

bool BuildInteractiveLaunchRequest(std::wstring_view requestId, std::wstring_view profileId,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    std::wstring_view leasePipe, std::wstring_view nonce, std::string& request)
{
    if (leasePipe.empty() || nonce.empty() || !IsValidUtf16(leasePipe) || !IsValidUtf16(nonce) ||
        !BeginLaunchRequest(
            requestId, profileId, "interactive", arguments, workingDirectory, request))
    {
        return false;
    }
    request += ",\"interactive\":{\"leasePipe\":";
    AppendJsonString(request, leasePipe);
    request += ",\"nonce\":";
    AppendJsonString(request, nonce);
    request += "}}";
    return request.size() <= MaximumMessageBytes;
}

ParseResult ParseBrokerRequest(std::string_view message, BrokerRequest& request)
{
    request = {};
    if (message.empty() || message.size() > MaximumMessageBytes)
    {
        return ParseResult::InvalidRequest;
    }

    enum class LaunchMode
    {
        Missing,
        Console,
        Interactive
    };
    JsonReader reader(message);
    std::wstring operationName;
    LaunchMode launchMode = LaunchMode::Missing;
    bool version = false;
    bool requestId = false;
    bool operation = false;
    bool profile = false;
    bool mode = false;
    bool arguments = false;
    bool workingDirectory = false;
    bool console = false;
    bool interactive = false;
    bool force = false;
    const bool parsed = ReadObject(reader,
        [&](std::wstring_view name)
        {
            if (name == L"version")
            {
                DWORD value = 0;
                return FirstSeen(version) && reader.Unsigned(value) && value == 1;
            }
            if (name == L"requestId")
            {
                return FirstSeen(requestId) && reader.String(request.requestId) &&
                       IsRequestId(request.requestId);
            }
            if (name == L"operation")
            {
                return FirstSeen(operation) && reader.String(operationName);
            }
            if (name == L"profileId")
            {
                return FirstSeen(profile) && reader.String(request.profileId) &&
                       IsValidProfileId(request.profileId);
            }
            if (name == L"mode")
            {
                std::wstring value;
                if (!FirstSeen(mode) || !reader.String(value))
                {
                    return false;
                }
                launchMode = value == L"console"       ? LaunchMode::Console
                             : value == L"interactive" ? LaunchMode::Interactive
                                                       : LaunchMode::Missing;
                return launchMode != LaunchMode::Missing;
            }
            if (name == L"arguments")
            {
                return FirstSeen(arguments) && ReadStringArray(reader,
                                                   request.arguments,
                                                   [](const std::wstring& argument)
                                                   { return argument.size() <= 8 * 1024; });
            }
            if (name == L"workingDirectory")
            {
                return FirstSeen(workingDirectory) && reader.String(request.workingDirectory) &&
                       !request.workingDirectory.empty() &&
                       request.workingDirectory.size() <= 32 * 1024;
            }
            if (name == L"console")
            {
                return FirstSeen(console) && ReadConsole(reader, request.console);
            }
            if (name == L"interactive")
            {
                return FirstSeen(interactive) && ReadInteractiveLaunch(reader, request.interactive);
            }
            if (name == L"force")
            {
                return FirstSeen(force) && reader.Boolean(request.force);
            }
            return false;
        });
    if (!parsed || !reader.End() || !version || !requestId || !operation)
    {
        return ParseResult::InvalidRequest;
    }
    if (operationName == L"list")
    {
        if (profile || mode || arguments || workingDirectory || console || interactive || force)
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = RequestOperation::List;
        return ParseResult::Success;
    }
    if (!profile || (force && operationName != L"takeover"))
    {
        return ParseResult::InvalidRequest;
    }
    if (operationName == L"create" || operationName == L"takeover" || operationName == L"forget" ||
        operationName == L"delete")
    {
        if (mode || arguments || workingDirectory || console || interactive)
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = operationName == L"create"     ? RequestOperation::Create
                            : operationName == L"takeover" ? RequestOperation::TakeOver
                            : operationName == L"forget"   ? RequestOperation::Forget
                                                           : RequestOperation::Delete;
        return ParseResult::Success;
    }
    if (operationName != L"launch" || !arguments || !workingDirectory)
    {
        return ParseResult::InvalidRequest;
    }
    if (launchMode == LaunchMode::Interactive)
    {
        if (console || !interactive || !IsInteractiveLeasePipeName(request.interactive.leasePipe) ||
            !IsRequestId(request.interactive.nonce))
        {
            return ParseResult::InvalidRequest;
        }
        request.operation = RequestOperation::InteractiveLaunch;
        return ParseResult::Success;
    }
    if (launchMode != LaunchMode::Console || !console || interactive ||
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

std::string BuildInteractiveLeaseAcquireRequest(
    std::wstring_view nonce, std::wstring_view childLogonSid)
{
    if (!IsRequestId(std::wstring(nonce)) || !IsLogonSid(childLogonSid))
    {
        return {};
    }
    std::string request = "{\"version\":1,\"operation\":\"acquire\",\"nonce\":";
    AppendJsonString(request, nonce);
    request += ",\"childLogonSid\":";
    AppendJsonString(request, childLogonSid);
    request += '}';
    return request;
}

std::string BuildInteractiveLeaseReleaseRequest(std::wstring_view nonce)
{
    if (!IsRequestId(std::wstring(nonce)))
    {
        return {};
    }
    std::string request = "{\"version\":1,\"operation\":\"release\",\"nonce\":";
    AppendJsonString(request, nonce);
    request += '}';
    return request;
}

bool ParseInteractiveLeaseRequest(
    std::string_view message, std::wstring_view expectedNonce, InteractiveLeaseRequest& request)
{
    request = {};
    if (message.empty() || message.size() > MaximumMessageBytes ||
        !IsRequestId(std::wstring(expectedNonce)))
    {
        return false;
    }
    JsonReader reader(message);
    std::wstring operationName;
    bool version = false;
    bool operation = false;
    bool nonce = false;
    bool childLogonSid = false;
    const bool parsed = ReadObject(reader,
        [&](std::wstring_view name)
        {
            if (name == L"version")
            {
                DWORD value = 0;
                return FirstSeen(version) && reader.Unsigned(value) && value == 1;
            }
            if (name == L"operation")
            {
                return FirstSeen(operation) && reader.String(operationName) &&
                       (operationName == L"acquire" || operationName == L"release");
            }
            if (name == L"nonce")
            {
                return FirstSeen(nonce) && reader.String(request.nonce) &&
                       request.nonce == expectedNonce;
            }
            if (name == L"childLogonSid")
            {
                return FirstSeen(childLogonSid) && reader.String(request.childLogonSid) &&
                       IsLogonSid(request.childLogonSid);
            }
            return false;
        });
    if (!parsed || !reader.End() || !version || !operation || !nonce)
    {
        return false;
    }
    // Acquire requires the child logon SID; release must not carry one.
    if (childLogonSid != (operationName == L"acquire"))
    {
        return false;
    }
    request.operation =
        childLogonSid ? InteractiveLeaseOperation::Acquire : InteractiveLeaseOperation::Release;
    return true;
}

std::string BuildInteractiveLeaseResponse(
    InteractiveLeaseOperation operation, std::wstring_view nonce, DWORD win32Error)
{
    if (!IsRequestId(std::wstring(nonce)))
    {
        return {};
    }
    std::string response = "{\"version\":1,\"operation\":";
    AppendJsonString(response, InteractiveLeaseOperationName(operation));
    response += ",\"nonce\":";
    AppendJsonString(response, nonce);
    response += win32Error == ERROR_SUCCESS ? ",\"status\":\"ok\",\"win32Error\":"
                                            : ",\"status\":\"error\",\"win32Error\":";
    response += std::to_string(win32Error);
    response += '}';
    return response;
}

bool ParseInteractiveLeaseResponse(std::string_view response,
    InteractiveLeaseOperation expectedOperation, std::wstring_view expectedNonce, DWORD& win32Error)
{
    win32Error = ERROR_INVALID_DATA;
    if (response.empty() || response.size() > MaximumMessageBytes ||
        !IsRequestId(std::wstring(expectedNonce)))
    {
        return false;
    }
    JsonReader reader(response);
    DWORD parsedError = ERROR_INVALID_DATA;
    bool statusIsOk = false;
    bool version = false;
    bool operation = false;
    bool nonce = false;
    bool status = false;
    bool error = false;
    const bool parsed = ReadObject(reader,
        [&](std::wstring_view name)
        {
            DWORD number = 0;
            std::wstring text;
            if (name == L"version")
            {
                return FirstSeen(version) && reader.Unsigned(number) && number == 1;
            }
            if (name == L"operation")
            {
                return FirstSeen(operation) && reader.String(text) &&
                       text == InteractiveLeaseOperationName(expectedOperation);
            }
            if (name == L"nonce")
            {
                return FirstSeen(nonce) && reader.String(text) && text == expectedNonce;
            }
            if (name == L"status")
            {
                if (!FirstSeen(status) || !reader.String(text))
                {
                    return false;
                }
                statusIsOk = text == L"ok";
                return statusIsOk || text == L"error";
            }
            if (name == L"win32Error")
            {
                return FirstSeen(error) && reader.Unsigned(parsedError);
            }
            return false;
        });
    if (!parsed || !reader.End() || !version || !operation || !nonce || !status || !error ||
        statusIsOk != (parsedError == ERROR_SUCCESS))
    {
        return false;
    }
    win32Error = parsedError;
    return true;
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
            return name == L"accounts" && FirstSeen(listedAccounts) &&
                   ReadStringArray(reader, accounts, IsValidProfileId);
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
            return name == L"processId" && FirstSeen(process) && reader.Unsigned(processId) &&
                   processId != 0;
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
        { return name == L"exitCode" && FirstSeen(exit) && reader.Unsigned(exitCode); });
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
            if (name == L"hostExitCode")
            {
                return FirstSeen(hostExit) && reader.Unsigned(hostExitCode);
            }
            return name == L"diagnostic" && FirstSeen(diagnostic) && reader.String(diagnostics);
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
