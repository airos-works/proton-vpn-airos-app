// Interoperability check of the userspace WireGuard engine with a real
// WireGuard peer (Linux's kernel implementation, see tests/wg-interop.sh).
// Runs entirely in user space: it encrypts hand-made ICMP echo requests from
// 10.2.0.2 to 10.2.0.1 and waits for the decrypted echo replies.
//   wg_interop <private key> <peer public key> <host> <port> [seconds]
#include "core/WireGuard.h"
#include "core/Util.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace pvpn;

static uint16_t Checksum(const uint8_t* data, size_t size)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2)
        sum += data[i] << 8 | data[i + 1];
    if (size & 1)
        sum += data[size - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static std::vector<uint8_t> EchoRequest(uint16_t sequence, size_t payload)
{
    std::vector<uint8_t> packet(20 + 8 + payload, 0);
    packet[0] = 0x45;
    packet[2] = packet.size() >> 8;
    packet[3] = packet.size() & 0xff;
    packet[8] = 64;     // TTL
    packet[9] = 1;      // ICMP
    uint8_t source[4] = {10, 2, 0, 2}, destination[4] = {10, 2, 0, 1};
    memcpy(&packet[12], source, 4);
    memcpy(&packet[16], destination, 4);
    uint16_t header = Checksum(packet.data(), 20);
    packet[10] = header >> 8;
    packet[11] = header & 0xff;
    uint8_t* icmp = &packet[20];
    icmp[0] = 8;        // echo request
    icmp[4] = 0x12;
    icmp[5] = 0x34;
    icmp[6] = sequence >> 8;
    icmp[7] = sequence & 0xff;
    for (size_t i = 0; i < payload; i++)
        icmp[8 + i] = (uint8_t)i;
    uint16_t sum = Checksum(icmp, 8 + payload);
    icmp[2] = sum >> 8;
    icmp[3] = sum & 0xff;
    return packet;
}

int main(int argc, char** argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s <private key> <peer public key> <host> <port> [seconds]\n", argv[0]);
        return 2;
    }
    wg::Key privateKey, peerKey;
    if (!wg::ParseKey(argv[1], privateKey) || !wg::ParseKey(argv[2], peerKey)) {
        fprintf(stderr, "bad keys\n");
        return 2;
    }
    double duration = argc > 5 ? atof(argv[5]) : 8;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in peer = {};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(atoi(argv[4]));
    inet_pton(AF_INET, argv[3], &peer.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);

    wg::Peer tunnel(privateKey, peerKey, 0);
    wg::Output out;
    int sent = 0, replies = 0, bigReplies = 0;
    double start = MonotonicNow(), lastPing = 0;
    while (MonotonicNow() - start < duration) {
        double now = MonotonicNow();
        if (now - lastPing >= 0.25 && sent < 20) {
            // Alternate small and near-MTU packets.
            std::vector<uint8_t> request = EchoRequest(sent, sent % 2 ? 1300 : 56);
            tunnel.SendPacket(request.data(), request.size(), now, out);
            sent++;
            lastPing = now;
        }
        for (auto& datagram : out.toNetwork)
            sendto(fd, datagram.data(), datagram.size(), 0, (sockaddr*)&peer, sizeof(peer));
        for (auto& packet : out.toTunnel) {
            if (packet.size() >= 28 && packet[9] == 1 && packet[20] == 0) {
                replies++;
                if (packet.size() > 1000)
                    bigReplies++;
            }
        }
        out.toNetwork.clear();
        out.toTunnel.clear();
        pollfd item = {fd, POLLIN, 0};
        poll(&item, 1, 50);
        uint8_t buffer[2048];
        ssize_t got;
        while ((got = recv(fd, buffer, sizeof(buffer), 0)) > 0)
            tunnel.ReceiveDatagram(buffer, got, MonotonicNow(), out);
        tunnel.Tick(MonotonicNow(), out);
        if (sent >= 20 && replies >= sent)
            break;
    }
    const wg::Stats& stats = tunnel.GetStats();
    printf("handshakes %u, sent %d, replies %d (%d large), bytes out %llu in %llu\n",
        stats.handshakes, sent, replies, bigReplies, (unsigned long long)stats.sentBytes,
        (unsigned long long)stats.receivedBytes);
    return stats.handshakes > 0 && replies >= sent - 2 && bigReplies > 0 ? 0 : 1;
}
