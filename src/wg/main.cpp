// proton-wireguard: runs one WireGuard tunnel for the Proton VPN app.
//
// The app starts it and writes one JSON line with the configuration to its
// standard input:
//   {"private_key": base64, "peer_public_key": base64, "endpoint": "1.2.3.4",
//    "port": 51820, "address": "10.2.0.2/32", "address6": "2a07:b944::2:2/128",
//    "mtu": 1420, "keepalive": 25, "routes": ["0.0.0.0/1", "128.0.0.0/1"],
//    "routes6": ["::/1", "8000::/1"], "handshake_timeout": 15}
// It answers with JSON lines on standard output:
//   {"event": "interface", "name": "tun/0"}, {"event": "handshake"},
//   {"event": "stats", "sent": n, "received": n}, {"event": "timeout"},
//   {"event": "error", "message": "..."}, {"event": "stopped"}
// It stops on {"command": "stop"} or when its standard input closes (the app
// went away), removing its routes and the tunnel interface.
#include "core/Json.h"
#include "core/Network.h"
#include "core/Util.h"
#include "core/WireGuard.h"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace pvpn;

namespace {

volatile sig_atomic_t sStop = 0;

void Emit(const Json& event)
{
    std::string line = event.dump() + "\n";
    if (fwrite(line.data(), 1, line.size(), stdout) != line.size()) {}
    fflush(stdout);
}

void EmitError(const std::string& message)
{
    Emit(Json{{"event", "error"}, {"message", message}});
}

void OnSignal(int)
{
    sStop = 1;
}

class Tunnel {
public:
    ~Tunnel() { TearDown(); }

    bool Setup(const Json& config, std::string& error);
    int Run(const Json& config);
    void TearDown();

private:
    bool AddRouteChecked(const Route& route, bool required, std::string& error);

    TunDevice fTun;
    int fSocket = -1;
    sockaddr_storage fEndpoint;
    socklen_t fEndpointLength = 0;
    std::vector<Route> fRoutes;   // added by us, removed in reverse order
    bool fIpv6 = false;
};


bool Tunnel::AddRouteChecked(const Route& route, bool required, std::string& error)
{
    std::string message;
    if (AddRoute(route, message)) {
        fRoutes.push_back(route);
        return true;
    }
    if (required) {
        error = message;
        return false;
    }
    Emit(Json{{"event", "log"}, {"message", message}});
    return true;
}


bool Tunnel::Setup(const Json& config, std::string& error)
{
    std::string endpoint = JsonString(config, "endpoint");
    int port = (int)JsonInt(config, "port", 51820);
    bool endpoint6 = endpoint.find(':') != std::string::npos;
    memset(&fEndpoint, 0, sizeof(fEndpoint));
    if (endpoint6) {
        sockaddr_in6& address = (sockaddr_in6&)fEndpoint;
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port);
        if (inet_pton(AF_INET6, endpoint.c_str(), &address.sin6_addr) != 1) {
            error = "bad endpoint " + endpoint;
            return false;
        }
        fEndpointLength = sizeof(sockaddr_in6);
    } else {
        sockaddr_in& address = (sockaddr_in&)fEndpoint;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (inet_pton(AF_INET, endpoint.c_str(), &address.sin_addr) != 1) {
            error = "bad endpoint " + endpoint;
            return false;
        }
        fEndpointLength = sizeof(sockaddr_in);
    }
#if defined(__HAIKU__)
    ((sockaddr*)&fEndpoint)->sa_len = fEndpointLength;
#endif

    // The tunnel's own traffic must keep using the current default route.
    Route original;
    if (!endpoint6 && FindDefaultRoute(original)) {
        Route bypass;
        bypass.interface = original.interface;
        bypass.destination = endpoint;
        bypass.prefix = 32;
        if (original.gateway != endpoint)
            bypass.gateway = original.gateway;
        AddRouteChecked(bypass, false, error);
    }

    fSocket = socket(endpoint6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fSocket < 0) {
        error = std::string("socket: ") + strerror(errno);
        return false;
    }
    fcntl(fSocket, F_SETFL, fcntl(fSocket, F_GETFL) | O_NONBLOCK);
    fcntl(fSocket, F_SETFD, FD_CLOEXEC);

    if (!fTun.Open(error))
        return false;
    Emit(Json{{"event", "interface"}, {"name", fTun.Name()}});

    std::string address;
    int prefix;
    if (!ParseCidr(JsonString(config, "address", "10.2.0.2/32"), address, prefix)) {
        error = "bad tunnel address";
        return false;
    }
    if (!fTun.SetAddress(address, prefix, JsonString(config, "peer_address"), error))
        return false;
    int mtu = (int)JsonInt(config, "mtu", 1420);
    std::string mtuError;
    if (!fTun.SetMtu(mtu, mtuError))
        Emit(Json{{"event", "log"}, {"message", mtuError}});
    if (!fTun.Up(error))
        return false;

    std::string address6 = JsonString(config, "address6");
    if (!address6.empty() && ParseCidr(address6, address, prefix)) {
        std::string message;
        if (fTun.SetAddress6(address, prefix, message))
            fIpv6 = true;
        else
            Emit(Json{{"event", "log"}, {"message", message}});
    }

    for (const Json& item : JsonArray(config, "routes")) {
        Route route;
        route.interface = fTun.Name();
        if (!item.is_string() || !ParseCidr(item.get<std::string>(), route.destination, route.prefix))
            continue;
        if (!AddRouteChecked(route, true, error))
            return false;
    }
    // IPv6 routes also serve as leak protection when the tunnel carries no
    // IPv6: such packets end here and are dropped.
    Route default6;
    if (fIpv6 || FindDefaultRoute6(default6)) {
        for (const Json& item : JsonArray(config, "routes6")) {
            Route route;
            route.interface = fTun.Name();
            if (item.is_string() && ParseCidr(item.get<std::string>(), route.destination, route.prefix))
                AddRouteChecked(route, false, error);
        }
    }
    return true;
}


void Tunnel::TearDown()
{
    for (auto it = fRoutes.rbegin(); it != fRoutes.rend(); ++it) {
        std::string error;
        DeleteRoute(*it, error);
    }
    fRoutes.clear();
    fTun.Close();
    if (fSocket >= 0) {
        close(fSocket);
        fSocket = -1;
    }
}


int Tunnel::Run(const Json& config)
{
    wg::Key privateKey, peerKey;
    if (!wg::ParseKey(JsonString(config, "private_key"), privateKey)
        || !wg::ParseKey(JsonString(config, "peer_public_key"), peerKey)) {
        EmitError("bad WireGuard keys");
        return 1;
    }
    wg::Peer peer(privateKey, peerKey, (int)JsonInt(config, "keepalive", 25));
    double handshakeTimeout = JsonDouble(config, "handshake_timeout", 15);
    double started = MonotonicNow();
    double lastStats = 0;
    bool handshakeReported = false;
    uint32_t handshakesSeen = 0;
    bool timeoutReported = false;
    std::string input;
    uint8_t buffer[65536];

    wg::Output out;
    peer.Initiate(MonotonicNow(), out);

    while (!sStop) {
        for (wg::Buffer& datagram : out.toNetwork) {
            if (sendto(fSocket, datagram.data(), datagram.size(), 0, (sockaddr*)&fEndpoint,
                    fEndpointLength) < 0 && errno != EAGAIN && errno != ENOBUFS) {
                // Usually transient (no route yet, network down).
            }
        }
        for (wg::Buffer& packet : out.toTunnel) {
            if (write(fTun.Fd(), packet.data(), packet.size()) < 0) {}
        }
        out.toNetwork.clear();
        out.toTunnel.clear();

        double now = MonotonicNow();
        const wg::Stats& stats = peer.GetStats();
        if (stats.handshakes != handshakesSeen) {
            handshakesSeen = stats.handshakes;
            Emit(Json{{"event", "handshake"}, {"count", stats.handshakes}});
            handshakeReported = true;
        }
        if (!handshakeReported && !timeoutReported && now - started >= handshakeTimeout) {
            Emit(Json{{"event", "timeout"}});
            timeoutReported = true;
        }
        if (now - lastStats >= 1) {
            lastStats = now;
            Emit(Json{{"event", "stats"}, {"sent", stats.sentBytes},
                {"received", stats.receivedBytes}, {"last_handshake", stats.lastHandshake > 0
                    ? now - stats.lastHandshake : -1}});
        }

        pollfd fds[3] = {
            {STDIN_FILENO, POLLIN, 0},
            {fSocket, POLLIN, 0},
            {fTun.Fd(), POLLIN, 0},
        };
        int ready = poll(fds, 3, 100);
        now = MonotonicNow();
        if (ready < 0 && errno != EINTR)
            break;
        if (ready > 0 && (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t got = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (got <= 0)
                break;   // the app went away
            input.append((const char*)buffer, got);
            size_t newline;
            bool stop = false;
            while ((newline = input.find('\n')) != std::string::npos) {
                Json command = ParseJson(input.substr(0, newline));
                input.erase(0, newline + 1);
                if (JsonString(command, "command") == "stop")
                    stop = true;
            }
            if (stop)
                break;
        }
        if (ready > 0 && (fds[1].revents & POLLIN)) {
            for (int i = 0; i < 64; i++) {
                sockaddr_storage from;
                socklen_t fromLength = sizeof(from);
                ssize_t got = recvfrom(fSocket, buffer, sizeof(buffer), 0, (sockaddr*)&from,
                    &fromLength);
                if (got <= 0)
                    break;
                peer.ReceiveDatagram(buffer, got, now, out);
            }
        }
        if (ready > 0 && (fds[2].revents & POLLIN)) {
            // Haiku's tunnel read blocks even in non-blocking mode: one read
            // per poll() wake-up.
            ssize_t got = read(fTun.Fd(), buffer, sizeof(buffer));
            if (got > 0) {
                bool v6 = (buffer[0] >> 4) == 6;
                if (!v6 || fIpv6)
                    peer.SendPacket(buffer, got, now, out);
            }
        }
        peer.Tick(now, out);
    }
    return 0;
}

}  // namespace


int main()
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, OnSignal);
    signal(SIGINT, OnSignal);

    // Unbuffered, so that later commands stay in the pipe for poll().
    std::string line;
    char c;
    while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n')
        line += c;
    Json config = ParseJson(line);
    if (config.is_discarded() || !config.is_object()) {
        EmitError("no configuration on standard input");
        return 1;
    }
    int status = 0;
    {
        Tunnel tunnel;
        std::string error;
        if (!tunnel.Setup(config, error)) {
            EmitError(error);
            status = 1;
        } else {
            status = tunnel.Run(config);
        }
    }
    Emit(Json{{"event", "stopped"}});
    return status;
}
