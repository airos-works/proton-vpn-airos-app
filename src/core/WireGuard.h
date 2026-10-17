// A userspace WireGuard peer for one remote peer, written from the protocol
// description (https://www.wireguard.com/protocol/ and the whitepaper):
// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshakes as initiator and responder,
// cookie replies, transport data with a replay window, and the timer rules
// (rekeying, retransmission, keepalives, key expiry). All cryptography comes
// from OpenSSL. The engine does no I/O: callers feed it packets from the tun
// device and datagrams from the network and send what it returns, so the same
// code runs in the Haiku helper and in the Linux tests.
#pragma once
#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace pvpn {
namespace wg {

typedef std::array<uint8_t, 32> Key;
typedef std::vector<uint8_t> Buffer;

// Protocol constants (whitepaper section 6.1).
const double kRekeyAfterTime = 120;
const double kRejectAfterTime = 180;
const double kRekeyAttemptTime = 90;
const double kRekeyTimeout = 5;
const double kKeepaliveTimeout = 10;
const double kCookieLifetime = 120;
const uint64_t kRekeyAfterMessages = 1ULL << 60;
const uint64_t kRejectAfterMessages = UINT64_MAX - (1ULL << 13);

bool ParseKey(const std::string& base64, Key& key);
std::string KeyToBase64(const Key& key);
bool PublicKeyFromPrivate(const Key& privateKey, Key& publicKey);
// A random private key (for tests and the fake server).
Key GeneratePrivateKey();

struct Output {
    std::vector<Buffer> toNetwork;   // UDP payloads for the peer's endpoint
    std::vector<Buffer> toTunnel;    // decrypted IP packets
};

struct Stats {
    uint64_t sentBytes = 0;        // IP payload bytes sent through the tunnel
    uint64_t receivedBytes = 0;
    uint64_t sentPackets = 0;
    uint64_t receivedPackets = 0;
    uint32_t handshakes = 0;
    double lastHandshake = 0;      // time of the last completed handshake
};

class Peer {
public:
    // persistentKeepalive: seconds, 0 to disable. psk may be all zero.
    Peer(const Key& staticPrivate, const Key& peerPublic, int persistentKeepalive = 0,
        const Key* presharedKey = nullptr);
    ~Peer();

    // An IP packet read from the tunnel device.
    void SendPacket(const uint8_t* packet, size_t size, double now, Output& out);
    // A datagram received from the peer's endpoint.
    void ReceiveDatagram(const uint8_t* data, size_t size, double now, Output& out);
    // Call regularly (every 100-250 ms).
    void Tick(double now, Output& out);
    // Starts a handshake now (e.g. right after start-up).
    void Initiate(double now, Output& out);

    bool HasSession(double now) const;
    // True once a handshake series has failed for kRekeyAttemptTime.
    bool HandshakeTimedOut() const { return fHandshakeTimedOut; }
    const Stats& GetStats() const { return fStats; }
    std::string LastError() const { return fLastError; }

private:
    struct Keypair;
    struct Handshake;

    void StartHandshake(double now, Output& out, bool retry);
    void SendInitiation(double now, Output& out);
    void HandleInitiation(const uint8_t* data, size_t size, double now, Output& out);
    void HandleResponse(const uint8_t* data, size_t size, double now, Output& out);
    void HandleCookie(const uint8_t* data, size_t size, double now);
    void HandleData(const uint8_t* data, size_t size, double now, Output& out);
    bool Encrypt(Keypair& keypair, const uint8_t* packet, size_t size, double now, Output& out);
    void SendKeepalive(double now, Output& out);
    void FlushQueue(double now, Output& out);
    void InstallKeypair(std::unique_ptr<Keypair> keypair, double now);
    uint32_t NewIndex() const;
    bool CheckMac1(const uint8_t* message, size_t macOffset) const;
    void AddMacs(uint8_t* message, size_t macOffset, double now);

    Key fStaticPrivate;
    Key fStaticPublic;
    Key fPeerPublic;
    Key fPresharedKey;
    uint8_t fPrecomputedStaticStatic[32];
    int fPersistentKeepalive;

    std::unique_ptr<Keypair> fCurrent;
    std::unique_ptr<Keypair> fPrevious;
    std::unique_ptr<Keypair> fNext;        // responder keys, until confirmed
    std::unique_ptr<Handshake> fHandshake; // our pending initiation

    uint8_t fLatestTimestamp[12] = {};     // greatest TAI64N seen from the peer
    uint8_t fCookie[16] = {};
    double fCookieTime = -1e9;
    uint8_t fLastMac1[16] = {};
    bool fHaveLastMac1 = false;

    std::deque<Buffer> fQueue;             // packets waiting for a session
    double fHandshakeStarted = 0;          // start of the current attempt series
    double fLastInitiationSent = -1e9;
    double fRetransmitJitter = 0;
    bool fHandshakeInProgress = false;
    bool fHandshakeTimedOut = false;
    double fLastSent = -1e9;               // any packet to the peer
    double fLastDataSent = -1e9;           // non-keepalive data
    double fLastReceived = -1e9;           // any authenticated packet from the peer
    double fLastDataReceived = -1e9;
    bool fWaitingForReply = false;         // data sent, nothing received since
    double fLastKeyActivity = 0;

    Stats fStats;
    std::string fLastError;
};

}  // namespace wg
}  // namespace pvpn
