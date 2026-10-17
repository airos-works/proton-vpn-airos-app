// Core tests; run with `make check` on Haiku or `make BUILD=build-host check-host` on Linux.
// The argument is the tests directory (test vectors live in tests/data).
#include "core/Crypto.h"
#include "core/Json.h"
#include "core/Modulus.h"
#include "core/Srp.h"
#include "core/Util.h"
#include "core/WireGuard.h"
#include "core/ServerList.h"
#include "core/Settings.h"
#include "core/ResolvConf.h"
#include <cstring>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace pvpn;

static int sFailures = 0;
static int sChecks = 0;
static std::string sTestsDir = "tests";

#define CHECK(condition) do { sChecks++; if (!(condition)) { sFailures++; \
    fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); } } while (0)
#define CHECK_EQ(a, b) do { sChecks++; auto _a = (a); auto _b = (b); if (!(_a == _b)) { \
    sFailures++; fprintf(stderr, "%s:%d: CHECK_EQ failed: %s\n", __FILE__, __LINE__, #a); } \
    } while (0)

static Json LoadJson(const std::string& name)
{
    std::string text;
    if (!ReadFile(sTestsDir + "/data/" + name, text)) {
        fprintf(stderr, "cannot read %s\n", name.c_str());
        sFailures++;
        return Json::object();
    }
    return Json::parse(text, nullptr, false);
}


static void TestUtil()
{
    CHECK_EQ(Base64Encode(std::string("hello")), std::string("aGVsbG8="));
    Bytes decoded;
    CHECK(Base64Decode("aGVs\nbG8=", decoded));
    CHECK_EQ(std::string(decoded.begin(), decoded.end()), std::string("hello"));
    CHECK(NaturalLess("CH#2", "CH#10"));
    CHECK(!NaturalLess("CH#10", "CH#2"));
    CHECK(NaturalLess("CH#9", "CH-FR#1") || NaturalLess("CH-FR#1", "CH#9"));
    CHECK(FoldedContains("Z\xc3\xbcrich", "zur"));
    CHECK(FoldedContains("S\xc3\xa3o Paulo", "sao"));
    CHECK(!FoldedContains("Berlin", "zur"));
}


static void TestKeys()
{
    Json vector = LoadJson("key-vector.json");
    Ed25519Key key;
    CHECK(Ed25519Key::FromSeed(Base64Decode(JsonString(vector, "seed")), key));
    CHECK_EQ(Base64Encode(key.PublicKey()), JsonString(vector, "ed_public"));
    CHECK_EQ(Base64Encode(key.X25519Private()), JsonString(vector, "x25519_private"));
    CHECK_EQ(Base64Encode(key.X25519Public()), JsonString(vector, "x25519_public"));
    CHECK_EQ(Base64Encode(Ed25519PublicToX25519(key.PublicKey())), JsonString(vector, "x25519_public"));
    CHECK_EQ(key.Fingerprint(), JsonString(vector, "fingerprint"));
    CHECK_EQ(key.PublicPem(), JsonString(vector, "public_pem"));
    CHECK_EQ(key.PrivatePem(), JsonString(vector, "private_pem"));
    Ed25519Key fresh = Ed25519Key::Generate();
    CHECK(fresh.IsValid());
    CHECK(fresh.Fingerprint() != key.Fingerprint());
}


static void TestModulus()
{
    Json info = LoadJson("auth-info.json");
    Bytes modulus;
    std::string error;
    CHECK(VerifyModulus(JsonString(info, "Modulus"), modulus, error));
    CHECK_EQ(modulus.size(), (size_t)256);
    // A changed digit must break the signature.
    std::string tampered = JsonString(info, "Modulus");
    size_t position = tampered.find("\n\n") + 5;
    tampered[position] = tampered[position] == 'A' ? 'B' : 'A';
    CHECK(!VerifyModulus(tampered, modulus, error));
}


static void TestSrp()
{
    Json vector = LoadJson("srp-vector.json");
    std::string error;
    Bytes modulus;
    CHECK(VerifyModulus(JsonString(vector, "modulus_armored"), modulus, error));
    Bytes salt = Base64Decode(JsonString(vector, "salt"));
    std::string password = JsonString(vector, "password");
    CHECK_EQ(ProtonBcrypt(password, salt), JsonString(vector, "bcrypt"));
    CHECK_EQ(Base64Encode(HashPassword(password, salt, modulus, 4)), JsonString(vector, "x_hash"));
    SrpClient client(password, modulus);
    client.SetSecretEphemeral(Base64Decode(JsonString(vector, "a")));
    CHECK_EQ(Base64Encode(client.Challenge()), JsonString(vector, "A"));
    Bytes proof;
    CHECK(client.ProcessChallenge(salt, Base64Decode(JsonString(vector, "server_ephemeral")),
        JsonInt(vector, "version"), proof));
    CHECK_EQ(Base64Encode(proof), JsonString(vector, "M"));
    CHECK(client.VerifyServerProof(Base64Decode(JsonString(vector, "expected_server_proof"))));
    CHECK(!client.VerifyServerProof(proof));
}


static std::vector<uint8_t> FakeIpPacket(size_t payload, uint8_t fill)
{
    std::vector<uint8_t> packet(20 + payload, fill);
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2] = (packet.size() >> 8) & 0xff;
    packet[3] = packet.size() & 0xff;
    return packet;
}


static void TestWireGuard()
{
    using namespace pvpn::wg;
    Key a = GeneratePrivateKey(), b = GeneratePrivateKey();
    Key aPublic, bPublic;
    CHECK(PublicKeyFromPrivate(a, aPublic));
    CHECK(PublicKeyFromPrivate(b, bPublic));
    Key parsed;
    CHECK(ParseKey(KeyToBase64(aPublic), parsed));
    CHECK(parsed == aPublic);

    Peer client(a, bPublic, 0);
    Peer server(b, aPublic, 0);
    double now = 1000;
    Output clientOut, serverOut;
    std::vector<uint8_t> first = FakeIpPacket(100, 0x11);
    client.SendPacket(first.data(), first.size(), now, clientOut);
    CHECK_EQ(clientOut.toNetwork.size(), (size_t)1);       // the initiation
    CHECK_EQ(clientOut.toNetwork[0].size(), (size_t)148);
    server.ReceiveDatagram(clientOut.toNetwork[0].data(), clientOut.toNetwork[0].size(), now, serverOut);
    CHECK_EQ(serverOut.toNetwork.size(), (size_t)1);       // the response
    CHECK_EQ(serverOut.toNetwork[0].size(), (size_t)92);
    Output clientOut2;
    client.ReceiveDatagram(serverOut.toNetwork[0].data(), serverOut.toNetwork[0].size(), now, clientOut2);
    CHECK(client.HasSession(now));
    CHECK_EQ(client.GetStats().handshakes, (uint32_t)1);
    // The queued packet goes out after the handshake.
    CHECK_EQ(clientOut2.toNetwork.size(), (size_t)1);
    Output serverOut2;
    for (auto& datagram : clientOut2.toNetwork)
        server.ReceiveDatagram(datagram.data(), datagram.size(), now, serverOut2);
    CHECK_EQ(serverOut2.toTunnel.size(), (size_t)1);
    CHECK(serverOut2.toTunnel.size() == 1 && serverOut2.toTunnel[0] == first);
    // A replayed datagram is dropped.
    Output replay;
    server.ReceiveDatagram(clientOut2.toNetwork[0].data(), clientOut2.toNetwork[0].size(), now, replay);
    CHECK(replay.toTunnel.empty());
    // The server answers with its now confirmed keys.
    std::vector<uint8_t> answer = FakeIpPacket(1300, 0x22);
    Output serverOut3, clientOut3;
    server.SendPacket(answer.data(), answer.size(), now + 1, serverOut3);
    CHECK_EQ(serverOut3.toNetwork.size(), (size_t)1);
    for (auto& datagram : serverOut3.toNetwork)
        client.ReceiveDatagram(datagram.data(), datagram.size(), now + 1, clientOut3);
    CHECK(clientOut3.toTunnel.size() == 1 && clientOut3.toTunnel[0] == answer);
    // A tampered datagram does not decrypt.
    Output tampered;
    std::vector<uint8_t> broken = serverOut3.toNetwork[0];
    broken[40] ^= 1;
    client.ReceiveDatagram(broken.data(), broken.size(), now + 1, tampered);
    CHECK(tampered.toTunnel.empty());

    // After REKEY_AFTER_TIME the initiator starts a new handshake while
    // still sending with the old keys.
    Output rekey;
    double later = now + kRekeyAfterTime + 1;
    client.SendPacket(first.data(), first.size(), later, rekey);
    CHECK_EQ(rekey.toNetwork.size(), (size_t)2);   // data + initiation
    Output serverRekey;
    for (auto& datagram : rekey.toNetwork)
        server.ReceiveDatagram(datagram.data(), datagram.size(), later, serverRekey);
    CHECK_EQ(serverRekey.toTunnel.size(), (size_t)1);
    CHECK_EQ(serverRekey.toNetwork.size(), (size_t)1);
    Output clientRekey;
    client.ReceiveDatagram(serverRekey.toNetwork[0].data(), serverRekey.toNetwork[0].size(), later, clientRekey);
    CHECK_EQ(client.GetStats().handshakes, (uint32_t)2);
    // The keepalive that confirms the new session reaches the server.
    Output serverConfirm;
    for (auto& datagram : clientRekey.toNetwork)
        server.ReceiveDatagram(datagram.data(), datagram.size(), later, serverConfirm);
    Output serverNew, clientNew;
    server.SendPacket(answer.data(), answer.size(), later, serverNew);
    for (auto& datagram : serverNew.toNetwork)
        client.ReceiveDatagram(datagram.data(), datagram.size(), later, clientNew);
    CHECK_EQ(clientNew.toTunnel.size(), (size_t)1);

    // A handshake nobody answers is retried and then given up.
    Peer lonely(a, bPublic, 0);
    Output lonelyOut;
    lonely.Initiate(0, lonelyOut);
    size_t initiations = lonelyOut.toNetwork.size();
    for (double t = 0; t < kRekeyAttemptTime + 10; t += 0.5)
        lonely.Tick(t, lonelyOut);
    CHECK(lonelyOut.toNetwork.size() - initiations >= 10);
    CHECK(lonely.HandshakeTimedOut());
}


int main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1)
        sTestsDir = argv[1];
    TestUtil();
    TestKeys();
    TestModulus();
    TestSrp();
    TestWireGuard();
    printf("%d checks, %d failures\n", sChecks, sFailures);
    return sFailures == 0 ? 0 : 1;
}
