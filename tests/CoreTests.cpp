// Core tests; run with `make check` on Haiku or `make BUILD=build-host check-host` on Linux.
// The argument is the tests directory (test vectors live in tests/data).
#include "core/Crypto.h"
#include "core/Json.h"
#include "core/Modulus.h"
#include "core/Srp.h"
#include "core/Util.h"
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


int main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1)
        sTestsDir = argv[1];
    TestUtil();
    TestKeys();
    TestModulus();
    TestSrp();
    printf("%d checks, %d failures\n", sChecks, sFailures);
    return sFailures == 0 ? 0 : 1;
}
