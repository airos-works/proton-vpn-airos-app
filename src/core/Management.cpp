#include "Management.h"
#include "Util.h"
#include <cstdlib>
#include <cstring>

namespace pvpn {

std::string ManagementQuote(const std::string& text)
{
    std::string result = "\"";
    for (char c : text) {
        if (c == '"' || c == '\\')
            result += '\\';
        result += c;
    }
    return result + "\"";
}


ManagementLine ParseManagementLine(const std::string& line)
{
    static const struct {
        const char* prefix;
        ManagementKind kind;
    } kPrefixes[] = {
        {">STATE:", ManagementKind::State}, {">PASSWORD:", ManagementKind::Password},
        {">BYTECOUNT:", ManagementKind::ByteCount}, {">LOG:", ManagementKind::Log},
        {">HOLD:", ManagementKind::Hold}, {">FATAL:", ManagementKind::Fatal},
        {">INFO:", ManagementKind::Info}, {">ECHO:", ManagementKind::Echo},
        {">NEED-OK:", ManagementKind::NeedOk}, {">NEED-STR:", ManagementKind::NeedStr},
        {"SUCCESS:", ManagementKind::Success}, {"ERROR:", ManagementKind::Error},
    };
    ManagementLine result;
    std::string text = line;
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n'))
        text.pop_back();
    for (const auto& prefix : kPrefixes) {
        if (StartsWith(text, std::string(prefix.prefix))) {
            result.kind = prefix.kind;
            result.payload = text.substr(strlen(prefix.prefix));
            if (!result.payload.empty() && result.payload[0] == ' ')
                result.payload.erase(0, 1);
            return result;
        }
    }
    result.payload = text;
    return result;
}


bool ParseState(const std::string& payload, StateInfo& state)
{
    // <time>,<state>,<description>,<local ip>,<remote ip>,<remote port>,...
    std::vector<std::string> fields = Split(payload, ',');
    if (fields.size() < 2)
        return false;
    state = StateInfo();
    state.name = fields[1];
    if (fields.size() > 2)
        state.description = fields[2];
    if (fields.size() > 3)
        state.localAddress = fields[3];
    if (fields.size() > 4)
        state.remoteAddress = fields[4];
    if (fields.size() > 5)
        state.remotePort = fields[5];
    return true;
}


std::string LogMessage(const std::string& payload)
{
    size_t first = payload.find(',');
    if (first == std::string::npos)
        return payload;
    size_t second = payload.find(',', first + 1);
    if (second == std::string::npos)
        return payload.substr(first + 1);
    return payload.substr(second + 1);
}


bool ParsePushReply(const std::string& message, PushedOptions& options)
{
    size_t start = message.find("PUSH_REPLY,");
    if (start == std::string::npos)
        return false;
    std::string body = message.substr(start + strlen("PUSH_REPLY,"));
    // The log wraps the reply in quotes: '...'
    size_t quote = body.rfind('\'');
    if (quote != std::string::npos)
        body.erase(quote);
    for (const std::string& option : Split(body, ',')) {
        std::vector<std::string> words;
        for (const std::string& word : Split(option, ' ')) {
            if (!word.empty())
                words.push_back(word);
        }
        if (words.empty())
            continue;
        if (words[0] == "dhcp-option" && words.size() >= 3) {
            if (words[1] == "DNS" || words[1] == "DNS6")
                options.dnsServers.push_back(words[2]);
            else if (words[1] == "DOMAIN" || words[1] == "DOMAIN-SEARCH"
                || words[1] == "ADAPTER_DOMAIN_SUFFIX")
                options.domains.push_back(words[2]);
        } else if (words[0] == "route" && words.size() >= 2)
            options.routes.push_back(words[1] + "/" + (words.size() >= 3 ? words[2] : "255.255.255.255"));
        else if (words[0] == "redirect-gateway")
            options.redirectGateway = true;
        else if (words[0] == "ifconfig" && words.size() >= 3)
            options.ifconfig = words[1] + " " + words[2];
    }
    return true;
}


bool ParseByteCount(const std::string& payload, uint64_t& received, uint64_t& sent)
{
    size_t comma = payload.find(',');
    if (comma == std::string::npos)
        return false;
    received = strtoull(payload.substr(0, comma).c_str(), nullptr, 10);
    sent = strtoull(payload.substr(comma + 1).c_str(), nullptr, 10);
    return true;
}

}  // namespace pvpn
