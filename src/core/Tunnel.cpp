#include "Tunnel.h"
#include "Json.h"
#include "Management.h"
#include "Util.h"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace pvpn {

namespace {

#ifdef MSG_NOSIGNAL
const int kSendFlags = MSG_NOSIGNAL;
#else
const int kSendFlags = 0;
#endif

// The tls-crypt key of OPENVPN_V2_TEMPLATE (python-proton-vpn-api-core,
// proton/vpn/backend/networkmanager/protocol/openvpn/openvpn.py).
const char kTlsCryptKey[] =
    "-----BEGIN OpenVPN Static key V1-----\n"
    "6acef03f62675b4b1bbd03e53b187727\n"
    "423cea742242106cb2916a8a4c829756\n"
    "3d22c7e5cef430b1103c6f66eb1fc5b3\n"
    "75a672f158e2e2e936c3faa48b035a6d\n"
    "e17beaac23b5f03b10b868d53d03521d\n"
    "8ba115059da777a60cbfd7b2c9c57472\n"
    "78a15b8f6e68a3ef7fd583ec9f398c8b\n"
    "d4735dab40cbd1e3c62a822e97489186\n"
    "c30a0b48c7c38ea32ceb056d3fa5a710\n"
    "e10ccc7a0ddb363b08c3d2777a3395e1\n"
    "0c0b6080f56309192ab5aacd4b45f55d\n"
    "a61fc77af39bd81a19218a79762c3386\n"
    "2df55785075f37d8c71dc8a42097ee43\n"
    "344739a0dd48d03025b0450cf1fb5e8c\n"
    "aeb893d9a96d1f15519bb3c4dcb40ee3\n"
    "16672ea16c012664f8a9f11255518deb\n"
    "-----END OpenVPN Static key V1-----\n";

void SetCloseOnExec(int fd)
{
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
}

std::string EnsureNewline(const std::string& text)
{
    return !text.empty() && text.back() != '\n' ? text + "\n" : text;
}

// The last meaningful line of an OpenVPN log, without its time stamp.
std::string LogTail(const std::string& path)
{
    std::string content;
    if (path.empty() || !ReadFile(path, content))
        return "";
    size_t end = content.find_last_not_of("\r\n");
    while (end != std::string::npos) {
        size_t start = content.rfind('\n', end);
        start = start == std::string::npos ? 0 : start + 1;
        std::string line = content.substr(start, end - start + 1);
        if (line.size() > 20 && line[4] == '-' && line[10] == ' ')
            line = line.substr(20);
        if (line.find("Exiting due to fatal error") == std::string::npos
            && line.find("SIGTERM") == std::string::npos && !line.empty())
            return line;
        if (start == 0)
            break;
        end = content.find_last_not_of("\r\n", start - 1);
    }
    return "";
}


class OpenVpnTunnel : public Tunnel {
public:
    OpenVpnTunnel(const TunnelConfig& config, TunnelListener* listener)
        : Tunnel(config, listener) {}
    ~OpenVpnTunnel() override;
    void Start() override;

private:
    void Run();
    bool Launch(int port, std::string& error);
    void Serve(int listenFd);
    void Handle(const std::string& line);
    bool Send(const std::string& command);
    void Fail(TunnelFailure failure, const std::string& message);

    int fManagementFd = -1;
    std::string fConfigPath;
    std::string fLogPath;
    PushedOptions fPushed;
    std::string fDevice;
    bool fUp = false;
    int fTlsFailures = 0;
    TunnelFailure fFailure = TunnelFailure::None;
    std::string fFailureMessage;
};


class WireGuardTunnel : public Tunnel {
public:
    WireGuardTunnel(const TunnelConfig& config, TunnelListener* listener)
        : Tunnel(config, listener) {}
    ~WireGuardTunnel() override;
    void Start() override;

private:
    void Run();
    void HandleEvent(const Json& event);

    int fInput = -1;
    int fOutput = -1;
    std::string fDevice;
    bool fUp = false;
    TunnelFailure fFailure = TunnelFailure::None;
    std::string fFailureMessage;
};

}  // namespace


std::string OpenVpnConfigText(const TunnelConfig& config)
{
    bool tcp = config.protocol == "openvpn-tcp";
    std::string text;
    if (config.ipv6)
        text += "push-peer-info\nsetenv UV_IPV6 1\n";
    text += "client\ndev tun\n";
    text += std::string("proto ") + (tcp ? "tcp" : "udp") + "\n\n";
    for (int port : config.ports)
        text += "remote " + config.serverIp + " " + std::to_string(port) + "\n";
    text +=
        "\nremote-random\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "cipher AES-256-GCM\n"
        "verb 3\n"
        "\n"
        "tun-mtu 1500\n"
        "mssfix 0\n"
        "persist-key\n"
        "persist-tun\n"
        "\n"
        "reneg-sec 0\n"
        "\n"
        "remote-cert-tls server\n";
    // NetworkManager adds this for the GTK app ("verify-x509-name name:<domain>").
    if (!config.domain.empty())
        text += "verify-x509-name " + config.domain + " name\n";
    // Instead of the pushed redirect-gateway's halves (0.0.0.0/1), route the
    // quarters of the address space through the tunnel, so that they win over
    // the kill switch's halves (see KillSwitch.h).
    text +=
        "\npull-filter ignore \"redirect-gateway\"\n"
        "route " + config.serverIp + " 255.255.255.255 net_gateway\n"
        "route 0.0.0.0 192.0.0.0\n"
        "route 64.0.0.0 192.0.0.0\n"
        "route 128.0.0.0 192.0.0.0\n"
        "route 192.0.0.0 192.0.0.0\n";
    if (config.ipv6)
        text += "route-ipv6 ::/2\nroute-ipv6 4000::/2\nroute-ipv6 8000::/2\nroute-ipv6 c000::/2\n";
    text += "\n<ca>\n" + EnsureNewline(config.openvpnCaPem) + "</ca>\n\n";
    text += std::string("<tls-crypt>\n") + kTlsCryptKey + "</tls-crypt>\n\n";
    text += "<cert>\n" + EnsureNewline(config.certificatePem) + "</cert>\n";
    text += "<key>\n" + EnsureNewline(config.privateKeyPem) + "</key>\n";
    return text;
}


Tunnel::Tunnel(const TunnelConfig& config, TunnelListener* listener)
    :
    fConfig(config),
    fListener(listener)
{
    if (pipe(fWakePipe) == 0) {
        SetCloseOnExec(fWakePipe[0]);
        SetCloseOnExec(fWakePipe[1]);
        fcntl(fWakePipe[0], F_SETFL, O_NONBLOCK);
    }
}


Tunnel::~Tunnel()
{
    if (fWakePipe[0] >= 0)
        close(fWakePipe[0]);
    if (fWakePipe[1] >= 0)
        close(fWakePipe[1]);
}


Tunnel* Tunnel::Create(const TunnelConfig& config, TunnelListener* listener)
{
    if (config.protocol == "wireguard")
        return new WireGuardTunnel(config, listener);
    return new OpenVpnTunnel(config, listener);
}


void Tunnel::Stop()
{
    fStopRequested = true;
    Wake();
}


void Tunnel::Wake()
{
    if (fWakePipe[1] >= 0) {
        char byte = 0;
        if (write(fWakePipe[1], &byte, 1) < 0) {}
    }
}


bool Tunnel::Spawn(const std::vector<std::string>& arguments, int* stdinFd, int* stdoutFd,
    const std::string& logPath, std::string& error)
{
    int input[2] = {-1, -1}, output[2] = {-1, -1};
    if ((stdinFd != nullptr && pipe(input) != 0) || (stdoutFd != nullptr && pipe(output) != 0)) {
        error = std::string("pipe: ") + strerror(errno);
        return false;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (stdinFd != nullptr) {
        posix_spawn_file_actions_adddup2(&actions, input[0], 0);
        posix_spawn_file_actions_addclose(&actions, input[1]);
    } else {
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    }
    if (stdoutFd != nullptr) {
        posix_spawn_file_actions_adddup2(&actions, output[1], 1);
        posix_spawn_file_actions_addclose(&actions, output[0]);
    } else {
        posix_spawn_file_actions_addopen(&actions, 1, logPath.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC, 0600);
    }
    if (!logPath.empty() && stdoutFd != nullptr)
        posix_spawn_file_actions_addopen(&actions, 2, logPath.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC, 0600);
    else
        posix_spawn_file_actions_adddup2(&actions, 1, 2);
    std::vector<std::string> args = arguments;
    std::vector<char*> argv;
    for (std::string& arg : args)
        argv.push_back(&arg[0]);
    argv.push_back(nullptr);
    pid_t pid = -1;
    int status = posix_spawn(&pid, argv[0], &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (stdinFd != nullptr)
        close(input[0]);
    if (stdoutFd != nullptr)
        close(output[1]);
    if (status != 0) {
        error = "cannot start " + arguments[0] + ": " + strerror(status);
        if (stdinFd != nullptr)
            close(input[1]);
        if (stdoutFd != nullptr)
            close(output[0]);
        return false;
    }
    if (stdinFd != nullptr) {
        SetCloseOnExec(input[1]);
        *stdinFd = input[1];
    }
    if (stdoutFd != nullptr) {
        SetCloseOnExec(output[0]);
        *stdoutFd = output[0];
    }
    fPid = pid;
    return true;
}


void Tunnel::Reap(int graceSeconds)
{
    if (fPid <= 0)
        return;
    int status = 0;
    bool exited = false;
    for (int i = 0; i < graceSeconds * 10 && !exited; i++) {
        exited = waitpid(fPid, &status, WNOHANG) == fPid;
        if (!exited)
            usleep(100000);
    }
    if (!exited) {
        fListener->TunnelLog("The VPN process did not exit; killing it.");
        kill(fPid, SIGKILL);
        waitpid(fPid, &status, 0);
    }
    fPid = -1;
}


// --- OpenVPN -------------------------------------------------------------------

OpenVpnTunnel::~OpenVpnTunnel()
{
    Stop();
    if (fThread.joinable())
        fThread.join();
}


void OpenVpnTunnel::Start()
{
    fThread = std::thread(&OpenVpnTunnel::Run, this);
}


void OpenVpnTunnel::Fail(TunnelFailure failure, const std::string& message)
{
    if (fFailure == TunnelFailure::None) {
        fFailure = failure;
        fFailureMessage = message;
    }
    fStopRequested = true;
}


void OpenVpnTunnel::Run()
{
    std::string error;
    int listenFd = -1;
    do {
        MakeDirectories(fConfig.runtimeDirectory, 0700);
        chmod(fConfig.runtimeDirectory.c_str(), 0700);
        // OpenVPN connects to us (--management-client), so no other local
        // program can take over its management interface.
        listenFd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        if (listenFd < 0 || bind(listenFd, (sockaddr*)&address, sizeof(address)) != 0
            || listen(listenFd, 1) != 0
            || getsockname(listenFd, (sockaddr*)&address, &length) != 0) {
            Fail(TunnelFailure::TunnelSetup, std::string("management socket: ") + strerror(errno));
            break;
        }
        SetCloseOnExec(listenFd);
        if (!Launch(ntohs(address.sin_port), error)) {
            Fail(TunnelFailure::TunnelSetup, error);
            break;
        }
        Serve(listenFd);
    } while (false);

    if (listenFd >= 0)
        close(listenFd);
    if (fManagementFd >= 0) {
        close(fManagementFd);
        fManagementFd = -1;
    }
    bool hadProcess = fPid > 0;
    Reap(8);
    if (!fConfigPath.empty())
        unlink(fConfigPath.c_str());
    std::string tail = LogTail(fLogPath);
    if (hadProcess && fFailure == TunnelFailure::None && !fStopRequested)
        fFailure = fUp ? TunnelFailure::Unexpected : TunnelFailure::TunnelSetup,
        fFailureMessage = tail.empty() ? "OpenVPN stopped." : tail;
    if (fFailure != TunnelFailure::None)
        fListener->TunnelFailed(fFailure, fFailureMessage);
    fListener->TunnelStopped();
}


bool OpenVpnTunnel::Launch(int port, std::string& error)
{
    fConfigPath = fConfig.runtimeDirectory + "/proton.ovpn";
    fLogPath = fConfig.runtimeDirectory + "/openvpn.log";
    if (!WriteFile(fConfigPath, OpenVpnConfigText(fConfig), 0600)) {
        error = "cannot write " + fConfigPath + ": " + strerror(errno);
        return false;
    }
    std::vector<std::string> args = {
        fConfig.openvpnPath,
        "--config", fConfigPath,
        "--management", "127.0.0.1", std::to_string(port),
        "--management-client", "--management-hold",
        "--script-security", "1",
        "--connect-retry", "2", "5",
        "--verb", "3",
    };
    if (!Spawn(args, nullptr, nullptr, fLogPath, error))
        return false;
    fListener->TunnelLog("Started OpenVPN (" + std::to_string(fPid) + ") for " + fConfig.serverIp
        + " (" + fConfig.protocol + ")");
    return true;
}


void OpenVpnTunnel::Serve(int listenFd)
{
    double deadline = MonotonicNow() + 20;
    while (fManagementFd < 0) {
        pollfd fds[2] = {{listenFd, POLLIN, 0}, {fWakePipe[0], POLLIN, 0}};
        int ready = poll(fds, 2, 250);
        if (fds[1].revents & POLLIN) {
            char buffer[64];
            while (read(fWakePipe[0], buffer, sizeof(buffer)) > 0) {}
        }
        if (fStopRequested) {
            kill(fPid, SIGTERM);
            return;
        }
        if (ready > 0 && (fds[0].revents & POLLIN)) {
            fManagementFd = accept(listenFd, nullptr, nullptr);
            if (fManagementFd >= 0)
                SetCloseOnExec(fManagementFd);
            break;
        }
        int status;
        if (waitpid(fPid, &status, WNOHANG) == fPid) {
            fPid = -1;
            std::string tail = LogTail(fLogPath);
            Fail(TunnelFailure::TunnelSetup, tail.empty() ? "OpenVPN exited during start-up." : tail);
            return;
        }
        if (MonotonicNow() > deadline) {
            Fail(TunnelFailure::TunnelSetup, "OpenVPN did not open its management connection.");
            kill(fPid, SIGTERM);
            return;
        }
    }

    Send("state on");
    Send("bytecount 2");
    Send("log on all");
    Send("hold release");

    std::string buffer;
    bool stopSent = false;
    double stopTime = 0;
    while (true) {
        if (fStopRequested && !stopSent) {
            Send("signal SIGTERM");
            stopSent = true;
            stopTime = MonotonicNow();
        }
        if (stopSent && MonotonicNow() > stopTime + 8)
            return;   // Run() kills it
        pollfd fds[2] = {{fManagementFd, POLLIN, 0}, {fWakePipe[0], POLLIN, 0}};
        int ready = poll(fds, 2, 1000);
        if (ready < 0 && errno != EINTR)
            return;
        if (fds[1].revents & POLLIN) {
            char drain[64];
            while (read(fWakePipe[0], drain, sizeof(drain)) > 0) {}
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char chunk[8192];
            ssize_t received = recv(fManagementFd, chunk, sizeof(chunk), 0);
            if (received <= 0)
                return;   // OpenVPN exited
            buffer.append(chunk, received);
            size_t newline;
            while ((newline = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, newline);
                buffer.erase(0, newline + 1);
                Handle(line);
            }
        }
    }
}


void OpenVpnTunnel::Handle(const std::string& text)
{
    ManagementLine line = ParseManagementLine(text);
    switch (line.kind) {
        case ManagementKind::Log: {
            std::string message = LogMessage(line.payload);
            fListener->TunnelLog(message);
            if (message.find("PUSH_REPLY,") != std::string::npos) {
                fPushed.Clear();
                ParsePushReply(message, fPushed);
            }
            size_t device = message.find("TUN/TAP device /dev/");
            if (device != std::string::npos) {
                std::string name = message.substr(device + 20);
                fDevice = name.substr(0, name.find(' '));
            }
            if (message.find("AUTH_FAILED") != std::string::npos)
                Fail(TunnelFailure::AuthDenied, "The VPN server refused the certificate.");
            if (message.find("TLS Error: TLS handshake failed") != std::string::npos
                || message.find("TLS key negotiation failed") != std::string::npos)
                fTlsFailures++;
            if (message.find("VERIFY ERROR") != std::string::npos
                || message.find("VERIFY X509NAME ERROR") != std::string::npos)
                Fail(TunnelFailure::AuthDenied, "The VPN server's certificate did not verify.");
            break;
        }
        case ManagementKind::State: {
            StateInfo state;
            if (!ParseState(line.payload, state))
                break;
            if (state.name == "CONNECTED") {
                fTlsFailures = 0;
                fUp = true;
                fListener->TunnelUp(fDevice, state.localAddress, fPushed.dnsServers);
            } else if (state.name == "RECONNECTING") {
                if (fUp)
                    fListener->TunnelReconnecting(state.description);
                fUp = false;
            }
            break;
        }
        case ManagementKind::ByteCount: {
            uint64_t received, sent;
            if (ParseByteCount(line.payload, received, sent))
                fListener->TunnelStats(received, sent);
            break;
        }
        case ManagementKind::Hold:
            Send("hold release");
            break;
        case ManagementKind::Password:
            // Certificate authentication only: a password query means the
            // configuration is not what we wrote.
            Fail(TunnelFailure::AuthDenied, "OpenVPN asked for a password.");
            break;
        case ManagementKind::Fatal:
            Fail(fUp ? TunnelFailure::Unexpected : TunnelFailure::TunnelSetup, line.payload);
            break;
        default:
            break;
    }
}


bool OpenVpnTunnel::Send(const std::string& command)
{
    if (fManagementFd < 0)
        return false;
    std::string line = command + "\n";
    size_t sent = 0;
    while (sent < line.size()) {
        ssize_t result = send(fManagementFd, line.data() + sent, line.size() - sent, kSendFlags);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            return false;
        sent += result;
    }
    return true;
}


// --- WireGuard -----------------------------------------------------------------

WireGuardTunnel::~WireGuardTunnel()
{
    Stop();
    if (fThread.joinable())
        fThread.join();
}


void WireGuardTunnel::Start()
{
    fThread = std::thread(&WireGuardTunnel::Run, this);
}


void WireGuardTunnel::HandleEvent(const Json& event)
{
    std::string name = JsonString(event, "event");
    if (name == "interface") {
        fDevice = JsonString(event, "name");
        fListener->TunnelLog("WireGuard interface " + fDevice);
    } else if (name == "handshake") {
        if (!fUp) {
            fUp = true;
            fListener->TunnelLog("WireGuard handshake completed");
            fListener->TunnelUp(fDevice, "10.2.0.2", {});
        }
    } else if (name == "stats") {
        fListener->TunnelStats((uint64_t)JsonInt(event, "received"), (uint64_t)JsonInt(event, "sent"));
        double age = JsonDouble(event, "last_handshake", -1);
        // No handshake for REJECT_AFTER_TIME and more: the server is gone.
        if (fUp && age > 3 * 60 + 30) {
            fUp = false;
            fListener->TunnelReconnecting("no handshake for " + std::to_string((int)age) + " s");
        } else if (!fUp && age >= 0 && age < 30 && !fDevice.empty()) {
            fUp = true;
            fListener->TunnelUp(fDevice, "10.2.0.2", {});
        }
    } else if (name == "timeout") {
        if (!fUp) {
            fFailure = TunnelFailure::Timeout;
            fFailureMessage = "The VPN server did not answer.";
            fStopRequested = true;
        }
    } else if (name == "error") {
        fFailure = fUp ? TunnelFailure::Unexpected : TunnelFailure::TunnelSetup;
        fFailureMessage = JsonString(event, "message");
        fListener->TunnelLog("WireGuard: " + fFailureMessage);
    } else if (name == "log") {
        fListener->TunnelLog("WireGuard: " + JsonString(event, "message"));
    }
}


void WireGuardTunnel::Run()
{
    std::string error;
    MakeDirectories(fConfig.runtimeDirectory, 0700);
    std::string logPath = fConfig.runtimeDirectory + "/wireguard.log";
    if (!Spawn({fConfig.wireguardPath}, &fInput, &fOutput, logPath, error)) {
        fListener->TunnelFailed(TunnelFailure::TunnelSetup, error);
        fListener->TunnelStopped();
        return;
    }
    Json config = {
        {"private_key", fConfig.wireguardPrivateKey},
        {"peer_public_key", fConfig.serverPublicKey},
        {"endpoint", fConfig.serverIp},
        {"port", fConfig.ports.empty() ? 51820 : fConfig.ports.front()},
        {"address", "10.2.0.2/32"},
        {"mtu", 1420},
        {"keepalive", 25},
        // Quarters, so that they win over the kill switch's halves.
        {"routes", {"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}},
        {"routes6", {"::/2", "4000::/2", "8000::/2", "c000::/2"}},
        {"handshake_timeout", 15},
    };
    if (fConfig.ipv6)
        config["address6"] = "2a07:b944::2:2/128";
    std::string line = config.dump() + "\n";
    if (write(fInput, line.data(), line.size()) != (ssize_t)line.size())
        fListener->TunnelLog("Could not configure the WireGuard helper.");
    fListener->TunnelLog("Started WireGuard (" + std::to_string(fPid) + ") for " + fConfig.serverIp
        + ":" + std::to_string(fConfig.ports.empty() ? 51820 : fConfig.ports.front()));

    std::string buffer;
    bool stopSent = false;
    double stopTime = 0;
    bool exited = false;
    while (!exited) {
        if (fStopRequested && !stopSent) {
            std::string stop = "{\"command\":\"stop\"}\n";
            if (write(fInput, stop.data(), stop.size()) < 0) {}
            stopSent = true;
            stopTime = MonotonicNow();
        }
        if (stopSent && MonotonicNow() > stopTime + 8)
            break;
        pollfd fds[2] = {{fOutput, POLLIN, 0}, {fWakePipe[0], POLLIN, 0}};
        int ready = poll(fds, 2, 1000);
        if (ready < 0 && errno != EINTR)
            break;
        if (fds[1].revents & POLLIN) {
            char drain[64];
            while (read(fWakePipe[0], drain, sizeof(drain)) > 0) {}
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char chunk[4096];
            ssize_t got = read(fOutput, chunk, sizeof(chunk));
            if (got <= 0) {
                exited = true;
                break;
            }
            buffer.append(chunk, got);
            size_t newline;
            while ((newline = buffer.find('\n')) != std::string::npos) {
                Json event = ParseJson(buffer.substr(0, newline));
                buffer.erase(0, newline + 1);
                if (!event.is_discarded())
                    HandleEvent(event);
            }
        }
    }
    close(fInput);
    fInput = -1;
    Reap(8);
    close(fOutput);
    fOutput = -1;
    if (fFailure == TunnelFailure::None && !fStopRequested) {
        fFailure = fUp ? TunnelFailure::Unexpected : TunnelFailure::TunnelSetup;
        fFailureMessage = "The WireGuard helper stopped.";
    }
    if (fFailure != TunnelFailure::None)
        fListener->TunnelFailed(fFailure, fFailureMessage);
    fListener->TunnelStopped();
}

}  // namespace pvpn
