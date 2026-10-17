// Key material for Proton VPN: the client's Ed25519 key (sent to the API to get a
// certificate, used for OpenVPN and the local agent's TLS) and the X25519 key
// derived from it (WireGuard). Also hashes, random bytes and certificate parsing,
// all through OpenSSL.
#pragma once
#include "Util.h"
#include <ctime>
#include <string>

namespace pvpn {

Bytes RandomBytes(size_t count);
Bytes Sha256(const uint8_t* data, size_t size);
Bytes Sha512(const uint8_t* data, size_t size);
Bytes Sha512(const std::string& data);
bool Ed25519Verify(const Bytes& publicKey, const uint8_t* message, size_t size,
    const Bytes& signature);

// Maps an Ed25519 public key to its X25519 (Montgomery) form, as libsodium's
// crypto_sign_ed25519_pk_to_curve25519 does. Returns an empty vector on error.
Bytes Ed25519PublicToX25519(const Bytes& edPublic);
// X25519 public key of a raw 32-byte X25519 private key.
Bytes X25519PublicFromPrivate(const Bytes& xPrivate);
// base64(SHA-512(x25519 public key)), Proton's key fingerprint.
std::string ProtonFingerprint(const Bytes& x25519Public);

class Ed25519Key {
public:
    // A fresh random key.
    static Ed25519Key Generate();
    // From the 32-byte seed (what Proton's apps store, base64-encoded).
    static bool FromSeed(const Bytes& seed, Ed25519Key& key);

    bool IsValid() const { return fSeed.size() == 32; }
    const Bytes& Seed() const { return fSeed; }
    const Bytes& PublicKey() const { return fPublic; }
    std::string SeedBase64() const { return Base64Encode(fSeed); }
    // PKCS#8 "BEGIN PRIVATE KEY" and SubjectPublicKeyInfo "BEGIN PUBLIC KEY".
    std::string PrivatePem() const;
    std::string PublicPem() const;

    // libsodium's crypto_sign_ed25519_sk_to_curve25519: the clamped first half
    // of SHA-512(seed).
    Bytes X25519Private() const;
    Bytes X25519Public() const;
    std::string WireGuardPrivateBase64() const { return Base64Encode(X25519Private()); }
    std::string Fingerprint() const { return ProtonFingerprint(X25519Public()); }

private:
    Bytes fSeed;
    Bytes fPublic;
};

struct CertificateInfo {
    time_t notBefore = 0;
    time_t notAfter = 0;
    Bytes edPublicKey;          // empty if the key is not Ed25519
    std::string fingerprint;    // ProtonFingerprint of the key's X25519 form
    std::string subject;
};

bool ParseCertificatePem(const std::string& pem, CertificateInfo& info);

}  // namespace pvpn
