#include "WireGuard.h"
#include "Util.h"
#include <bitset>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace pvpn {
namespace wg {

namespace {

const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const char kLabelMac1[] = "mac1----";
const char kLabelCookie[] = "cookie--";

enum MessageType : uint8_t {
    kInitiation = 1,
    kResponse = 2,
    kCookieReply = 3,
    kTransportData = 4,
};

const size_t kInitiationSize = 148;
const size_t kResponseSize = 92;
const size_t kCookieReplySize = 64;
const size_t kDataHeaderSize = 16;
const size_t kTagSize = 16;
const size_t kMaxQueued = 256;


// --- BLAKE2s (RFC 7693) -----------------------------------------------------

const uint32_t kBlake2sIv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

const uint8_t kBlake2sSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline uint32_t Rotr32(uint32_t value, int bits)
{
    return (value >> bits) | (value << (32 - bits));
}

inline uint32_t Load32(const uint8_t* p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

inline void Store32(uint8_t* p, uint32_t value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

inline void Store64(uint8_t* p, uint64_t value)
{
    for (int i = 0; i < 8; i++)
        p[i] = value >> (8 * i);
}

inline uint64_t Load64(const uint8_t* p)
{
    uint64_t value = 0;
    for (int i = 7; i >= 0; i--)
        value = value << 8 | p[i];
    return value;
}

class Blake2s {
public:
    Blake2s(size_t outputSize, const uint8_t* key = nullptr, size_t keySize = 0)
        :
        fOutputSize(outputSize)
    {
        memcpy(fState, kBlake2sIv, sizeof(fState));
        fState[0] ^= 0x01010000 ^ (keySize << 8) ^ outputSize;
        if (keySize > 0) {
            uint8_t block[64] = {};
            memcpy(block, key, keySize);
            Update(block, 64);
        }
    }

    void Update(const uint8_t* data, size_t size)
    {
        while (size > 0) {
            if (fBufferSize == 64) {
                fCounter += 64;
                Compress(false);
                fBufferSize = 0;
            }
            size_t take = std::min(size, 64 - fBufferSize);
            memcpy(fBuffer + fBufferSize, data, take);
            fBufferSize += take;
            data += take;
            size -= take;
        }
    }

    void Final(uint8_t* out)
    {
        fCounter += fBufferSize;
        memset(fBuffer + fBufferSize, 0, 64 - fBufferSize);
        Compress(true);
        uint8_t full[32];
        for (int i = 0; i < 8; i++)
            Store32(full + 4 * i, fState[i]);
        memcpy(out, full, fOutputSize);
    }

private:
    void Compress(bool last)
    {
        uint32_t m[16], v[16];
        for (int i = 0; i < 16; i++)
            m[i] = Load32(fBuffer + 4 * i);
        for (int i = 0; i < 8; i++) {
            v[i] = fState[i];
            v[i + 8] = kBlake2sIv[i];
        }
        v[12] ^= (uint32_t)fCounter;
        v[13] ^= (uint32_t)(fCounter >> 32);
        if (last)
            v[14] = ~v[14];
        auto g = [&](int a, int b, int c, int d, uint32_t x, uint32_t y) {
            v[a] = v[a] + v[b] + x;
            v[d] = Rotr32(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = Rotr32(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = Rotr32(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = Rotr32(v[b] ^ v[c], 7);
        };
        for (int round = 0; round < 10; round++) {
            const uint8_t* s = kBlake2sSigma[round];
            g(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++)
            fState[i] ^= v[i] ^ v[i + 8];
    }

    uint32_t fState[8];
    uint8_t fBuffer[64];
    size_t fBufferSize = 0;
    uint64_t fCounter = 0;
    size_t fOutputSize;
};

void Hash(uint8_t out[32], const uint8_t* a, size_t aSize, const uint8_t* b = nullptr,
    size_t bSize = 0)
{
    Blake2s hash(32);
    hash.Update(a, aSize);
    if (b != nullptr)
        hash.Update(b, bSize);
    hash.Final(out);
}

void Mac(uint8_t out[16], const uint8_t* key, size_t keySize, const uint8_t* data, size_t size)
{
    Blake2s mac(16, key, keySize);
    mac.Update(data, size);
    mac.Final(out);
}

// HMAC-BLAKE2s-256 (block size 64).
void Hmac(uint8_t out[32], const uint8_t* key, size_t keySize, const uint8_t* data, size_t size)
{
    uint8_t block[64] = {};
    if (keySize > 64)
        Hash(block, key, keySize);
    else
        memcpy(block, key, keySize);
    uint8_t pad[64];
    for (int i = 0; i < 64; i++)
        pad[i] = block[i] ^ 0x36;
    uint8_t inner[32];
    Blake2s innerHash(32);
    innerHash.Update(pad, 64);
    innerHash.Update(data, size);
    innerHash.Final(inner);
    for (int i = 0; i < 64; i++)
        pad[i] = block[i] ^ 0x5c;
    Blake2s outerHash(32);
    outerHash.Update(pad, 64);
    outerHash.Update(inner, 32);
    outerHash.Final(out);
}

// KDF_n(key, input) from the whitepaper, n = 1..3.
void Kdf(const uint8_t key[32], const uint8_t* input, size_t size, uint8_t* out1,
    uint8_t* out2 = nullptr, uint8_t* out3 = nullptr)
{
    uint8_t secret[32], t1[32], t2[32], t3[32];
    Hmac(secret, key, 32, input, size);
    uint8_t one = 1;
    Hmac(t1, secret, 32, &one, 1);
    memcpy(out1, t1, 32);
    if (out2 != nullptr) {
        uint8_t buffer[33];
        memcpy(buffer, t1, 32);
        buffer[32] = 2;
        Hmac(t2, secret, 32, buffer, 33);
        memcpy(out2, t2, 32);
        if (out3 != nullptr) {
            memcpy(buffer, t2, 32);
            buffer[32] = 3;
            Hmac(t3, secret, 32, buffer, 33);
            memcpy(out3, t3, 32);
        }
    }
    OPENSSL_cleanse(secret, sizeof(secret));
}


// --- ChaCha20-Poly1305 through OpenSSL, HChaCha20 for XChaCha20 ---------------

bool Aead(bool encrypt, const uint8_t key[32], const uint8_t nonce[12], const uint8_t* in,
    size_t size, const uint8_t* aad, size_t aadSize, uint8_t* out)
{
    // encrypt: out = ciphertext (size) || tag; decrypt: in = ciphertext || tag
    // (size includes the tag) and out = plaintext (size - 16).
    if (!encrypt && size < kTagSize)
        return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return false;
    bool ok = EVP_CipherInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr,
        encrypt ? 1 : 0) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1
        && EVP_CipherInit_ex(ctx, nullptr, nullptr, key, nonce, encrypt ? 1 : 0) == 1;
    int length = 0;
    if (ok && aadSize > 0)
        ok = EVP_CipherUpdate(ctx, nullptr, &length, aad, (int)aadSize) == 1;
    size_t textSize = encrypt ? size : size - kTagSize;
    if (ok && !encrypt)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kTagSize,
            (void*)(in + textSize)) == 1;
    if (ok && textSize > 0)
        ok = EVP_CipherUpdate(ctx, out, &length, in, (int)textSize) == 1;
    if (ok)
        ok = EVP_CipherFinal_ex(ctx, out + textSize, &length) == 1;
    if (ok && encrypt)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, kTagSize, out + textSize) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void CounterNonce(uint8_t nonce[12], uint64_t counter)
{
    memset(nonce, 0, 4);
    Store64(nonce + 4, counter);
}

inline uint32_t Rotl32(uint32_t value, int bits)
{
    return (value << bits) | (value >> (32 - bits));
}

void HChaCha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[16])
{
    uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; i++)
        x[4 + i] = Load32(key + 4 * i);
    for (int i = 0; i < 4; i++)
        x[12 + i] = Load32(nonce + 4 * i);
    auto quarter = [&](int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = Rotl32(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = Rotl32(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = Rotl32(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = Rotl32(x[b] ^ x[c], 7);
    };
    for (int i = 0; i < 10; i++) {
        quarter(0, 4, 8, 12);
        quarter(1, 5, 9, 13);
        quarter(2, 6, 10, 14);
        quarter(3, 7, 11, 15);
        quarter(0, 5, 10, 15);
        quarter(1, 6, 11, 12);
        quarter(2, 7, 8, 13);
        quarter(3, 4, 9, 14);
    }
    for (int i = 0; i < 4; i++) {
        Store32(out + 4 * i, x[i]);
        Store32(out + 16 + 4 * i, x[12 + i]);
    }
}

bool XAeadDecrypt(const uint8_t key[32], const uint8_t nonce[24], const uint8_t* in, size_t size,
    const uint8_t* aad, size_t aadSize, uint8_t* out)
{
    uint8_t subkey[32], shortNonce[12] = {};
    HChaCha20(subkey, key, nonce);
    memcpy(shortNonce + 4, nonce + 16, 8);
    bool ok = Aead(false, subkey, shortNonce, in, size, aad, aadSize, out);
    OPENSSL_cleanse(subkey, sizeof(subkey));
    return ok;
}


// --- X25519 -------------------------------------------------------------------

bool Dh(uint8_t out[32], const uint8_t privateKey[32], const uint8_t publicKey[32])
{
    EVP_PKEY* ours = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey, 32);
    EVP_PKEY* theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, publicKey, 32);
    EVP_PKEY_CTX* ctx = ours != nullptr ? EVP_PKEY_CTX_new(ours, nullptr) : nullptr;
    size_t size = 32;
    bool ok = ctx != nullptr && theirs != nullptr && EVP_PKEY_derive_init(ctx) == 1
        && EVP_PKEY_derive_set_peer(ctx, theirs) == 1 && EVP_PKEY_derive(ctx, out, &size) == 1
        && size == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(theirs);
    EVP_PKEY_free(ours);
    if (ok) {
        // An all-zero result means a low-order point.
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++)
            acc |= out[i];
        ok = acc != 0;
    }
    return ok;
}

void Tai64n(uint8_t out[12], double now)
{
    uint64_t seconds = (uint64_t)now;
    uint32_t nanoseconds = (uint32_t)((now - (double)seconds) * 1e9);
    // Lower the precision a little, as wireguard-go does.
    nanoseconds &= ~((1u << 24) - 1) & 0xffffffff;
    uint64_t label = 0x400000000000000aULL + seconds;
    for (int i = 0; i < 8; i++)
        out[i] = label >> (56 - 8 * i);
    for (int i = 0; i < 4; i++)
        out[8 + i] = nanoseconds >> (24 - 8 * i);
}

void RandomFill(uint8_t* out, size_t size)
{
    if (RAND_bytes(out, (int)size) != 1) {
        for (size_t i = 0; i < size; i++)
            out[i] = (uint8_t)(RandomUnit() * 256);
    }
}

// Size of the IP packet in a decrypted payload (which carries padding).
size_t IpPacketSize(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    int version = data[0] >> 4;
    if (version == 4 && size >= 20) {
        size_t total = (size_t)data[2] << 8 | data[3];
        return total >= 20 && total <= size ? total : 0;
    }
    if (version == 6 && size >= 40) {
        size_t total = 40 + ((size_t)data[4] << 8 | data[5]);
        return total <= size ? total : 0;
    }
    return 0;
}

}  // namespace


struct Peer::Keypair {
    uint8_t sendKey[32];
    uint8_t receiveKey[32];
    uint32_t localIndex = 0;
    uint32_t remoteIndex = 0;
    uint64_t sendCounter = 0;
    double created = 0;
    bool initiator = false;
    // Replay window over the highest counter seen.
    uint64_t greatest = 0;
    bool any = false;
    std::bitset<2048> window;

    ~Keypair()
    {
        OPENSSL_cleanse(sendKey, sizeof(sendKey));
        OPENSSL_cleanse(receiveKey, sizeof(receiveKey));
    }

    bool CounterAcceptable(uint64_t counter) const
    {
        if (counter >= kRejectAfterMessages)
            return false;
        if (!any || counter > greatest)
            return true;
        uint64_t behind = greatest - counter;
        return behind < window.size() && !window.test(behind);
    }

    void MarkCounter(uint64_t counter)
    {
        if (!any) {
            any = true;
            greatest = counter;
            window.reset();
            window.set(0);
            return;
        }
        if (counter > greatest) {
            uint64_t shift = counter - greatest;
            if (shift >= window.size())
                window.reset();
            else
                window <<= shift;
            greatest = counter;
            window.set(0);
        } else {
            window.set(greatest - counter);
        }
    }
};

struct Peer::Handshake {
    uint32_t localIndex = 0;
    uint8_t ephemeralPrivate[32];
    uint8_t ephemeralPublic[32];
    uint8_t chainingKey[32];
    uint8_t hash[32];

    ~Handshake()
    {
        OPENSSL_cleanse(ephemeralPrivate, sizeof(ephemeralPrivate));
        OPENSSL_cleanse(chainingKey, sizeof(chainingKey));
    }
};


bool ParseKey(const std::string& base64, Key& key)
{
    Bytes bytes;
    if (!Base64Decode(base64, bytes) || bytes.size() != 32)
        return false;
    memcpy(key.data(), bytes.data(), 32);
    return true;
}


std::string KeyToBase64(const Key& key)
{
    return Base64Encode(key.data(), key.size());
}


bool PublicKeyFromPrivate(const Key& privateKey, Key& publicKey)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), 32);
    size_t size = 32;
    bool ok = pkey != nullptr
        && EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &size) == 1 && size == 32;
    EVP_PKEY_free(pkey);
    return ok;
}


Key GeneratePrivateKey()
{
    Key key;
    RandomFill(key.data(), key.size());
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    return key;
}


Peer::Peer(const Key& staticPrivate, const Key& peerPublic, int persistentKeepalive,
    const Key* presharedKey)
    :
    fStaticPrivate(staticPrivate),
    fPeerPublic(peerPublic),
    fPersistentKeepalive(persistentKeepalive)
{
    PublicKeyFromPrivate(fStaticPrivate, fStaticPublic);
    if (presharedKey != nullptr)
        fPresharedKey = *presharedKey;
    else
        fPresharedKey.fill(0);
    if (!Dh(fPrecomputedStaticStatic, fStaticPrivate.data(), fPeerPublic.data())) {
        memset(fPrecomputedStaticStatic, 0, 32);
        fLastError = "invalid peer public key";
    }
}


Peer::~Peer()
{
    OPENSSL_cleanse(fStaticPrivate.data(), fStaticPrivate.size());
    OPENSSL_cleanse(fPrecomputedStaticStatic, sizeof(fPrecomputedStaticStatic));
}


bool Peer::HasSession(double now) const
{
    return fCurrent && now - fCurrent->created < kRejectAfterTime
        && fCurrent->sendCounter < kRejectAfterMessages;
}


uint32_t Peer::NewIndex() const
{
    while (true) {
        uint32_t index;
        RandomFill((uint8_t*)&index, sizeof(index));
        bool used = (fCurrent && fCurrent->localIndex == index)
            || (fPrevious && fPrevious->localIndex == index)
            || (fNext && fNext->localIndex == index)
            || (fHandshake && fHandshake->localIndex == index);
        if (!used && index != 0)
            return index;
    }
}


bool Peer::CheckMac1(const uint8_t* message, size_t macOffset) const
{
    uint8_t key[32], mac[16];
    Hash(key, (const uint8_t*)kLabelMac1, 8, fStaticPublic.data(), 32);
    Mac(mac, key, 32, message, macOffset);
    return CRYPTO_memcmp(mac, message + macOffset, 16) == 0;
}


void Peer::AddMacs(uint8_t* message, size_t macOffset, double now)
{
    uint8_t key[32];
    Hash(key, (const uint8_t*)kLabelMac1, 8, fPeerPublic.data(), 32);
    Mac(message + macOffset, key, 32, message, macOffset);
    memcpy(fLastMac1, message + macOffset, 16);
    fHaveLastMac1 = true;
    if (now - fCookieTime < kCookieLifetime)
        Mac(message + macOffset + 16, fCookie, 16, message, macOffset + 16);
    else
        memset(message + macOffset + 16, 0, 16);
}


void Peer::Initiate(double now, Output& out)
{
    StartHandshake(now, out, false);
}


void Peer::StartHandshake(double now, Output& out, bool retry)
{
    if (fHandshakeInProgress && !retry)
        return;
    if (!fHandshakeInProgress) {
        fHandshakeInProgress = true;
        fHandshakeTimedOut = false;
        fHandshakeStarted = now;
    }
    // At most one initiation per REKEY_TIMEOUT.
    if (!retry && now - fLastInitiationSent < kRekeyTimeout)
        return;
    SendInitiation(now, out);
}


void Peer::SendInitiation(double now, Output& out)
{
    fHandshake.reset(new Handshake);
    Handshake& h = *fHandshake;
    h.localIndex = NewIndex();
    Key ephemeral = GeneratePrivateKey();
    memcpy(h.ephemeralPrivate, ephemeral.data(), 32);
    Key ephemeralPublic;
    PublicKeyFromPrivate(ephemeral, ephemeralPublic);
    memcpy(h.ephemeralPublic, ephemeralPublic.data(), 32);
    OPENSSL_cleanse(ephemeral.data(), 32);

    Buffer message(kInitiationSize, 0);
    message[0] = kInitiation;
    Store32(&message[4], h.localIndex);

    Hash(h.chainingKey, (const uint8_t*)kConstruction, strlen(kConstruction));
    Hash(h.hash, h.chainingKey, 32, (const uint8_t*)kIdentifier, strlen(kIdentifier));
    Hash(h.hash, h.hash, 32, fPeerPublic.data(), 32);
    Kdf(h.chainingKey, h.ephemeralPublic, 32, h.chainingKey);
    memcpy(&message[8], h.ephemeralPublic, 32);
    Hash(h.hash, h.hash, 32, h.ephemeralPublic, 32);

    uint8_t shared[32], key[32], nonce[12];
    CounterNonce(nonce, 0);
    if (!Dh(shared, h.ephemeralPrivate, fPeerPublic.data())) {
        fLastError = "handshake key agreement failed";
        return;
    }
    Kdf(h.chainingKey, shared, 32, h.chainingKey, key);
    Aead(true, key, nonce, fStaticPublic.data(), 32, h.hash, 32, &message[40]);
    Hash(h.hash, h.hash, 32, &message[40], 48);

    Kdf(h.chainingKey, fPrecomputedStaticStatic, 32, h.chainingKey, key);
    uint8_t timestamp[12];
    Tai64n(timestamp, now);
    Aead(true, key, nonce, timestamp, 12, h.hash, 32, &message[88]);
    Hash(h.hash, h.hash, 32, &message[88], 28);
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(key, sizeof(key));

    AddMacs(message.data(), 116, now);
    fLastInitiationSent = now;
    fRetransmitJitter = RandomUnit() * 0.333;
    fLastSent = now;
    out.toNetwork.push_back(std::move(message));
}


void Peer::InstallKeypair(std::unique_ptr<Keypair> keypair, double now)
{
    if (keypair->initiator) {
        // Our own handshake: usable at once.
        if (fNext) {
            fPrevious = std::move(fNext);
        } else {
            fPrevious = std::move(fCurrent);
        }
        fCurrent = std::move(keypair);
    } else {
        // The responder waits for the initiator's first data packet.
        fNext = std::move(keypair);
    }
    fStats.handshakes++;
    fStats.lastHandshake = now;
    fLastKeyActivity = now;
}


void Peer::HandleInitiation(const uint8_t* data, size_t size, double now, Output& out)
{
    if (size != kInitiationSize || !CheckMac1(data, 116))
        return;
    uint8_t chainingKey[32], hash[32], shared[32], key[32], nonce[12];
    CounterNonce(nonce, 0);
    Hash(chainingKey, (const uint8_t*)kConstruction, strlen(kConstruction));
    Hash(hash, chainingKey, 32, (const uint8_t*)kIdentifier, strlen(kIdentifier));
    Hash(hash, hash, 32, fStaticPublic.data(), 32);
    const uint8_t* initiatorEphemeral = data + 8;
    Kdf(chainingKey, initiatorEphemeral, 32, chainingKey);
    Hash(hash, hash, 32, initiatorEphemeral, 32);
    if (!Dh(shared, fStaticPrivate.data(), initiatorEphemeral))
        return;
    Kdf(chainingKey, shared, 32, chainingKey, key);
    uint8_t initiatorStatic[32];
    if (!Aead(false, key, nonce, data + 40, 48, hash, 32, initiatorStatic))
        return;
    if (CRYPTO_memcmp(initiatorStatic, fPeerPublic.data(), 32) != 0)
        return;
    Hash(hash, hash, 32, data + 40, 48);
    Kdf(chainingKey, fPrecomputedStaticStatic, 32, chainingKey, key);
    uint8_t timestamp[12];
    if (!Aead(false, key, nonce, data + 88, 28, hash, 32, timestamp))
        return;
    // Replayed or old initiations are ignored.
    if (memcmp(timestamp, fLatestTimestamp, 12) <= 0)
        return;
    memcpy(fLatestTimestamp, timestamp, 12);
    Hash(hash, hash, 32, data + 88, 28);

    Buffer message(kResponseSize, 0);
    message[0] = kResponse;
    std::unique_ptr<Keypair> keypair(new Keypair);
    keypair->localIndex = NewIndex();
    keypair->remoteIndex = Load32(data + 4);
    Store32(&message[4], keypair->localIndex);
    memcpy(&message[8], data + 4, 4);
    Key ephemeral = GeneratePrivateKey();
    Key ephemeralPublic;
    PublicKeyFromPrivate(ephemeral, ephemeralPublic);
    Kdf(chainingKey, ephemeralPublic.data(), 32, chainingKey);
    memcpy(&message[12], ephemeralPublic.data(), 32);
    Hash(hash, hash, 32, ephemeralPublic.data(), 32);
    if (!Dh(shared, ephemeral.data(), initiatorEphemeral))
        return;
    Kdf(chainingKey, shared, 32, chainingKey);
    if (!Dh(shared, ephemeral.data(), fPeerPublic.data()))
        return;
    Kdf(chainingKey, shared, 32, chainingKey);
    OPENSSL_cleanse(ephemeral.data(), 32);
    uint8_t tau[32];
    Kdf(chainingKey, fPresharedKey.data(), 32, chainingKey, tau, key);
    Hash(hash, hash, 32, tau, 32);
    Aead(true, key, nonce, nullptr, 0, hash, 32, &message[44]);
    Hash(hash, hash, 32, &message[44], 16);
    // The responder receives with the first key and sends with the second.
    Kdf(chainingKey, nullptr, 0, keypair->receiveKey, keypair->sendKey);
    keypair->created = now;
    keypair->initiator = false;
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(chainingKey, sizeof(chainingKey));

    AddMacs(message.data(), 60, now);
    fLastSent = now;
    fLastReceived = now;
    out.toNetwork.push_back(std::move(message));
    InstallKeypair(std::move(keypair), now);
}


void Peer::HandleResponse(const uint8_t* data, size_t size, double now, Output& out)
{
    if (size != kResponseSize || !fHandshake || !CheckMac1(data, 60))
        return;
    if (Load32(data + 8) != fHandshake->localIndex)
        return;
    Handshake& h = *fHandshake;
    uint8_t chainingKey[32], hash[32], shared[32], key[32], nonce[12], tau[32];
    memcpy(chainingKey, h.chainingKey, 32);
    memcpy(hash, h.hash, 32);
    CounterNonce(nonce, 0);
    const uint8_t* responderEphemeral = data + 12;
    Kdf(chainingKey, responderEphemeral, 32, chainingKey);
    Hash(hash, hash, 32, responderEphemeral, 32);
    if (!Dh(shared, h.ephemeralPrivate, responderEphemeral))
        return;
    Kdf(chainingKey, shared, 32, chainingKey);
    if (!Dh(shared, fStaticPrivate.data(), responderEphemeral))
        return;
    Kdf(chainingKey, shared, 32, chainingKey);
    Kdf(chainingKey, fPresharedKey.data(), 32, chainingKey, tau, key);
    Hash(hash, hash, 32, tau, 32);
    uint8_t empty[1];
    if (!Aead(false, key, nonce, data + 44, 16, hash, 32, empty)) {
        fLastError = "handshake response did not authenticate";
        return;
    }
    std::unique_ptr<Keypair> keypair(new Keypair);
    Kdf(chainingKey, nullptr, 0, keypair->sendKey, keypair->receiveKey);
    keypair->localIndex = h.localIndex;
    keypair->remoteIndex = Load32(data + 4);
    keypair->created = now;
    keypair->initiator = true;
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(chainingKey, sizeof(chainingKey));
    fHandshake.reset();
    fHandshakeInProgress = false;
    fHandshakeTimedOut = false;
    fLastReceived = now;
    InstallKeypair(std::move(keypair), now);
    FlushQueue(now, out);
    // Confirms the session for the responder, which may not send before it.
    if (fLastSent < now)
        SendKeepalive(now, out);
}


void Peer::HandleCookie(const uint8_t* data, size_t size, double now)
{
    if (size != kCookieReplySize || !fHandshake || !fHaveLastMac1)
        return;
    if (Load32(data + 4) != fHandshake->localIndex)
        return;
    uint8_t key[32];
    Hash(key, (const uint8_t*)kLabelCookie, 8, fPeerPublic.data(), 32);
    uint8_t cookie[16];
    if (!XAeadDecrypt(key, data + 8, data + 32, 32, fLastMac1, 16, cookie))
        return;
    memcpy(fCookie, cookie, 16);
    fCookieTime = now;
}


void Peer::HandleData(const uint8_t* data, size_t size, double now, Output& out)
{
    if (size < kDataHeaderSize + kTagSize)
        return;
    uint32_t receiver = Load32(data + 4);
    Keypair* keypair = nullptr;
    bool fromNext = false;
    if (fCurrent && fCurrent->localIndex == receiver)
        keypair = fCurrent.get();
    else if (fPrevious && fPrevious->localIndex == receiver)
        keypair = fPrevious.get();
    else if (fNext && fNext->localIndex == receiver) {
        keypair = fNext.get();
        fromNext = true;
    }
    if (keypair == nullptr || now - keypair->created >= kRejectAfterTime)
        return;
    uint64_t counter = Load64(data + 8);
    if (!keypair->CounterAcceptable(counter))
        return;
    uint8_t nonce[12];
    CounterNonce(nonce, counter);
    Buffer plain(size - kDataHeaderSize - kTagSize);
    if (!Aead(false, keypair->receiveKey, nonce, data + kDataHeaderSize, size - kDataHeaderSize,
            nullptr, 0, plain.data()))
        return;
    keypair->MarkCounter(counter);
    if (fromNext) {
        fPrevious = std::move(fCurrent);
        fCurrent = std::move(fNext);
    }
    fLastReceived = now;
    fWaitingForReply = false;
    if (plain.empty())
        return;   // keepalive
    size_t packetSize = IpPacketSize(plain.data(), plain.size());
    if (packetSize == 0)
        return;
    plain.resize(packetSize);
    fLastDataReceived = now;
    fStats.receivedBytes += packetSize;
    fStats.receivedPackets++;
    out.toTunnel.push_back(std::move(plain));
    // Our keys are getting old and the peer will not rekey for us.
    if (fCurrent && fCurrent->initiator
        && now - fCurrent->created >= kRejectAfterTime - kKeepaliveTimeout - kRekeyTimeout)
        StartHandshake(now, out, false);
}


bool Peer::Encrypt(Keypair& keypair, const uint8_t* packet, size_t size, double now, Output& out)
{
    size_t padded = (size + 15) & ~(size_t)15;
    Buffer message(kDataHeaderSize + padded + kTagSize, 0);
    message[0] = kTransportData;
    Store32(&message[4], keypair.remoteIndex);
    uint64_t counter = keypair.sendCounter++;
    Store64(&message[8], counter);
    Buffer plain(padded, 0);
    if (size > 0)
        memcpy(plain.data(), packet, size);
    uint8_t nonce[12];
    CounterNonce(nonce, counter);
    if (!Aead(true, keypair.sendKey, nonce, plain.data(), padded, nullptr, 0,
            &message[kDataHeaderSize]))
        return false;
    fLastSent = now;
    if (size > 0) {
        if (!fWaitingForReply) {
            fWaitingForReply = true;
            fLastDataSent = now;
        }
        fStats.sentBytes += size;
        fStats.sentPackets++;
    }
    out.toNetwork.push_back(std::move(message));
    return true;
}


void Peer::SendPacket(const uint8_t* packet, size_t size, double now, Output& out)
{
    if (!HasSession(now)) {
        if (fQueue.size() >= kMaxQueued)
            fQueue.pop_front();
        fQueue.emplace_back(packet, packet + size);
        StartHandshake(now, out, false);
        return;
    }
    Encrypt(*fCurrent, packet, size, now, out);
    if (fCurrent->initiator && (now - fCurrent->created >= kRekeyAfterTime
            || fCurrent->sendCounter >= kRekeyAfterMessages))
        StartHandshake(now, out, false);
}


void Peer::SendKeepalive(double now, Output& out)
{
    if (HasSession(now))
        Encrypt(*fCurrent, nullptr, 0, now, out);
    else
        StartHandshake(now, out, false);
}


void Peer::FlushQueue(double now, Output& out)
{
    while (!fQueue.empty() && HasSession(now)) {
        Buffer packet = std::move(fQueue.front());
        fQueue.pop_front();
        Encrypt(*fCurrent, packet.data(), packet.size(), now, out);
    }
}


void Peer::ReceiveDatagram(const uint8_t* data, size_t size, double now, Output& out)
{
    if (size < 4 || data[1] != 0 || data[2] != 0 || data[3] != 0)
        return;
    switch (data[0]) {
        case kInitiation:
            HandleInitiation(data, size, now, out);
            break;
        case kResponse:
            HandleResponse(data, size, now, out);
            break;
        case kCookieReply:
            HandleCookie(data, size, now);
            break;
        case kTransportData:
            HandleData(data, size, now, out);
            break;
        default:
            break;
    }
}


void Peer::Tick(double now, Output& out)
{
    if (fHandshakeInProgress
        && now - fLastInitiationSent >= kRekeyTimeout + fRetransmitJitter) {
        if (now - fHandshakeStarted >= kRekeyAttemptTime) {
            fHandshakeInProgress = false;
            fHandshakeTimedOut = true;
            fHandshake.reset();
            fQueue.clear();
            fLastError = "no handshake response from the server";
        } else {
            SendInitiation(now, out);
        }
    }
    bool session = HasSession(now);
    // Passive keepalive: data arrived and we have had nothing to say since.
    if (session && fLastDataReceived > fLastSent && now - fLastDataReceived >= kKeepaliveTimeout)
        SendKeepalive(now, out);
    // Sent data but heard nothing back: the session may be dead.
    if (fWaitingForReply && now - fLastDataSent >= kKeepaliveTimeout + kRekeyTimeout) {
        fWaitingForReply = false;
        StartHandshake(now, out, false);
    }
    if (fPersistentKeepalive > 0 && now - fLastSent >= fPersistentKeepalive)
        SendKeepalive(now, out);
    if (fCurrent && now - fCurrent->created >= kRejectAfterTime * 3) {
        fCurrent.reset();
        fPrevious.reset();
        fNext.reset();
    }
    if (fPrevious && now - fPrevious->created >= kRejectAfterTime)
        fPrevious.reset();
    if (fNext && now - fNext->created >= kRejectAfterTime)
        fNext.reset();
}

}  // namespace wg
}  // namespace pvpn
