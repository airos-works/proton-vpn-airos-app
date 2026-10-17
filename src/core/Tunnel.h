// The VPN tunnel itself, one per connection attempt: OpenVPN (Proton's
// OPENVPN_V2_TEMPLATE, certificate authentication, run as proton-openvpn and
// driven through its management interface) or WireGuard (the
// proton-wireguard helper). A tunnel reports through TunnelListener on its
// own thread; the connector turns those reports into connection states.
#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <sys/types.h>
#include <thread>
#include <vector>

namespace pvpn {

struct TunnelConfig {
    std::string protocol;          // wireguard, openvpn-udp, openvpn-tcp
    std::string serverIp;          // the physical server's entry IP
    std::string domain;            // its TLS name
    std::string serverPublicKey;   // WireGuard: the physical server's X25519 key
    std::vector<int> ports;        // candidates, the first is used for WireGuard
    bool ipv6 = false;
    // Credentials from the API certificate.
    std::string certificatePem;
    std::string privateKeyPem;     // Ed25519, PKCS#8
    std::string wireguardPrivateKey;
    // Where things are.
    std::string runtimeDirectory;  // private scratch directory
    std::string openvpnPath;
    std::string wireguardPath;
    std::string openvpnCaPem;
};

enum class TunnelFailure {
    None,
    Timeout,          // the server did not answer
    AuthDenied,       // the server refused our certificate
    TunnelSetup,      // tun device, routes or the helper failed
    Unexpected,       // the tunnel went down by itself
};

class TunnelListener {
public:
    virtual ~TunnelListener() {}
    // The tunnel carries traffic; dns holds pushed name servers (OpenVPN).
    virtual void TunnelUp(const std::string& device, const std::string& localAddress,
        const std::vector<std::string>& dns) = 0;
    // A running tunnel lost its server and is trying to get it back.
    virtual void TunnelReconnecting(const std::string& reason) = 0;
    virtual void TunnelFailed(TunnelFailure failure, const std::string& message) = 0;
    // Stopped after Stop() or after a failure; the last call for a tunnel.
    virtual void TunnelStopped() = 0;
    virtual void TunnelStats(uint64_t received, uint64_t sent) = 0;
    virtual void TunnelLog(const std::string& line) = 0;
};

class Tunnel {
public:
    Tunnel(const TunnelConfig& config, TunnelListener* listener);
    virtual ~Tunnel();

    virtual void Start() = 0;
    // Asks the tunnel to stop; TunnelStopped follows.
    void Stop();
    const TunnelConfig& Config() const { return fConfig; }

    static Tunnel* Create(const TunnelConfig& config, TunnelListener* listener);

protected:
    void Wake();
    bool Spawn(const std::vector<std::string>& args, int* stdinFd, int* stdoutFd,
        const std::string& logPath, std::string& error);
    void Reap(int graceSeconds);

    TunnelConfig fConfig;
    TunnelListener* fListener;
    std::thread fThread;
    std::atomic<bool> fStopRequested{false};
    int fWakePipe[2] = {-1, -1};
    pid_t fPid = -1;
};

// The OpenVPN configuration for a server (exposed for tests).
std::string OpenVpnConfigText(const TunnelConfig& config);

}  // namespace pvpn
