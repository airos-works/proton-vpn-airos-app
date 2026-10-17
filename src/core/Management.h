// OpenVPN management interface messages (from Burrow, the author's AWS
// Client VPN app for Haiku).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace pvpn {

// Quotes a management command parameter.
std::string ManagementQuote(const std::string& text);

enum class ManagementKind {
    State, Password, ByteCount, Log, Hold, Fatal, Info, Echo, NeedOk, NeedStr,
    Success, Error, Other
};

struct ManagementLine {
    ManagementKind kind = ManagementKind::Other;
    std::string payload;   // text after ">KIND:" or "SUCCESS: "
};

ManagementLine ParseManagementLine(const std::string& line);

struct StateInfo {
    std::string name;         // CONNECTING, WAIT, AUTH, GET_CONFIG, CONNECTED, ...
    std::string description;  // SUCCESS, ERROR, reason for RECONNECTING, ...
    std::string localAddress;
    std::string remoteAddress;
    std::string remotePort;
};

bool ParseState(const std::string& payload, StateInfo& state);

// ">LOG:<time>,<flags>,<message>" payload's message.
std::string LogMessage(const std::string& payload);

// Options the server pushed, gathered from "PUSH_REPLY" log lines.
struct PushedOptions {
    std::vector<std::string> dnsServers;
    std::vector<std::string> domains;
    std::vector<std::string> routes;      // "network/netmask"
    bool redirectGateway = false;
    std::string ifconfig;                 // "local netmask-or-peer"

    void Clear() { *this = PushedOptions(); }
};

// Adds the options of a "PUSH: Received control message: 'PUSH_REPLY,...'"
// message; false when the message is not a push reply.
bool ParsePushReply(const std::string& message, PushedOptions& options);

bool ParseByteCount(const std::string& payload, uint64_t& received, uint64_t& sent);

}  // namespace pvpn
