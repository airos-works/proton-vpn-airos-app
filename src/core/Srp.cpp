#include "Srp.h"
#include "Crypto.h"
#include <cstring>
#include <openssl/bn.h>

extern "C" {
#include "crypt_blowfish/crypt_blowfish.h"
}

namespace pvpn {

namespace {

const size_t kSrpLength = 256;


Bytes ToLittleEndian(const BIGNUM* value)
{
    Bytes out(kSrpLength);
    if (BN_bn2lebinpad(value, out.data(), kSrpLength) < 0)
        out.clear();
    return out;
}

void Append(Bytes& out, const Bytes& data)
{
    out.insert(out.end(), data.begin(), data.end());
}

std::string BcryptBase64(const Bytes& data)
{
    static const char kStandard[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char kBcrypt[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string text = Base64Encode(data);
    for (char& c : text) {
        const char* position = strchr(kStandard, c);
        if (position != NULL && c != '\0')
            c = kBcrypt[position - kStandard];
    }
    return text;
}

}  // namespace


struct SrpClient::Numbers {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N = BN_new();
    BIGNUM* g = BN_new();
    BIGNUM* k = BN_new();
    BIGNUM* a = BN_new();
    BIGNUM* A = BN_new();

    ~Numbers()
    {
        BN_clear_free(a);
        BN_free(A);
        BN_free(k);
        BN_free(g);
        BN_free(N);
        BN_CTX_free(ctx);
    }
};


Bytes PmHash(const Bytes& data)
{
    Bytes out;
    Bytes input = data;
    input.push_back(0);
    for (uint8_t i = 0; i < 4; i++) {
        input.back() = i;
        Append(out, Sha512(input.data(), input.size()));
    }
    return out;
}


std::string ProtonBcrypt(const std::string& password, const Bytes& salt)
{
    Bytes extended = salt;
    const char* suffix = "proton";
    extended.insert(extended.end(), suffix, suffix + 6);
    extended.resize(16);
    std::string setting = "$2y$10$" + BcryptBase64(extended).substr(0, 22);
    // bcrypt only reads 72 bytes; Proton truncates explicitly to the same effect.
    std::string key = password.substr(0, 72);
    char output[64];
    memset(output, 0, sizeof(output));
    if (_crypt_blowfish_rn(key.c_str(), setting.c_str(), output, sizeof(output)) == NULL)
        return std::string();
    return output;
}


Bytes HashPassword(const std::string& password, const Bytes& salt, const Bytes& modulus,
    int version)
{
    if (version != 3 && version != 4)
        return Bytes();
    std::string hashed = ProtonBcrypt(password, salt);
    if (hashed.size() != 60)
        return Bytes();
    Bytes input(hashed.begin(), hashed.end());
    Append(input, modulus);
    return PmHash(input);
}


SrpClient::SrpClient(const std::string& password, const Bytes& modulus)
    :
    fNumbers(new Numbers),
    fPassword(password),
    fModulus(modulus)
{
    BN_lebin2bn(modulus.data(), (int)modulus.size(), fNumbers->N);
    BN_set_word(fNumbers->g, 2);
    Bytes input = ToLittleEndian(fNumbers->g);
    Append(input, ToLittleEndian(fNumbers->N));
    Bytes k = PmHash(input);
    BN_lebin2bn(k.data(), (int)k.size(), fNumbers->k);
    // a: 256 random bits with the top bit set, as get_random_of_length(32).
    Bytes a = RandomBytes(32);
    a[31] |= 0x80;
    SetSecretEphemeral(a);
}


SrpClient::~SrpClient()
{
    delete fNumbers;
}


void SrpClient::SetSecretEphemeral(const Bytes& a)
{
    BN_lebin2bn(a.data(), (int)a.size(), fNumbers->a);
    BN_mod_exp(fNumbers->A, fNumbers->g, fNumbers->a, fNumbers->N, fNumbers->ctx);
}


Bytes SrpClient::Challenge()
{
    return ToLittleEndian(fNumbers->A);
}


bool SrpClient::ProcessChallenge(const Bytes& salt, const Bytes& serverEphemeral, int version,
    Bytes& clientProof)
{
    Numbers& n = *fNumbers;
    if (BN_num_bytes(n.N) == 0 || serverEphemeral.size() != kSrpLength)
        return false;
    BN_CTX* ctx = n.ctx;
    BN_CTX_start(ctx);
    BIGNUM* B = BN_CTX_get(ctx);
    BIGNUM* u = BN_CTX_get(ctx);
    BIGNUM* x = BN_CTX_get(ctx);
    BIGNUM* v = BN_CTX_get(ctx);
    BIGNUM* kv = BN_CTX_get(ctx);
    BIGNUM* base = BN_CTX_get(ctx);
    BIGNUM* exponent = BN_CTX_get(ctx);
    BIGNUM* S = BN_CTX_get(ctx);
    BIGNUM* reduced = BN_CTX_get(ctx);
    bool ok = S != NULL;

    if (ok) {
        BN_lebin2bn(serverEphemeral.data(), (int)serverEphemeral.size(), B);
        // SRP-6a safety check: B mod N must not be zero.
        ok = BN_mod(reduced, B, n.N, ctx) && !BN_is_zero(reduced);
    }
    Bytes A = ToLittleEndian(n.A);
    Bytes Bbytes = ToLittleEndian(B);
    if (ok) {
        Bytes input = A;
        Append(input, Bbytes);
        Bytes hash = PmHash(input);
        BN_lebin2bn(hash.data(), (int)hash.size(), u);
        ok = !BN_is_zero(u);
    }
    if (ok) {
        Bytes hash = HashPassword(fPassword, salt, ToLittleEndian(n.N), version);
        ok = !hash.empty();
        if (ok)
            BN_lebin2bn(hash.data(), (int)hash.size(), x);
    }
    if (ok) {
        // S = (B - k * g^x) ^ (a + u * x) mod N
        ok = BN_mod_exp(v, n.g, x, n.N, ctx)
            && BN_mod_mul(kv, n.k, v, n.N, ctx)
            && BN_mod_sub(base, B, kv, n.N, ctx)
            && BN_mul(exponent, u, x, ctx)
            && BN_add(exponent, exponent, n.a)
            && BN_mod_exp(S, base, exponent, n.N, ctx);
    }
    if (ok) {
        fSessionKey = ToLittleEndian(S);
        Bytes input = A;
        Append(input, Bbytes);
        Append(input, fSessionKey);
        clientProof = PmHash(input);
        Bytes serverInput = A;
        Append(serverInput, clientProof);
        Append(serverInput, fSessionKey);
        fExpectedServerProof = PmHash(serverInput);
    }
    BN_CTX_end(ctx);
    return ok;
}


bool SrpClient::VerifyServerProof(const Bytes& serverProof) const
{
    return !fExpectedServerProof.empty() && serverProof == fExpectedServerProof;
}

}  // namespace pvpn
