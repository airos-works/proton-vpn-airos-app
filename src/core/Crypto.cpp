#include "Crypto.h"
#include <cstring>
#include <memory>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace pvpn {

namespace {

struct PkeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
typedef std::unique_ptr<EVP_PKEY, PkeyDeleter> PkeyPtr;

struct BioDeleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};
typedef std::unique_ptr<BIO, BioDeleter> BioPtr;

struct BnCtxDeleter {
    void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); }
};

struct BnDeleter {
    void operator()(BIGNUM* bn) const { BN_free(bn); }
};
typedef std::unique_ptr<BIGNUM, BnDeleter> BnPtr;

std::string BioString(BIO* bio)
{
    char* data = NULL;
    long size = BIO_get_mem_data(bio, &data);
    return std::string(data, size > 0 ? size : 0);
}

time_t AsnTime(const ASN1_TIME* time)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (time == NULL || ASN1_TIME_to_tm(time, &tm) != 1)
        return 0;
    // ASN1_TIME_to_tm gives UTC; timegm is not POSIX, so convert by hand.
    int year = tm.tm_year + 1900, month = tm.tm_mon + 1;
    int a = (14 - month) / 12;
    int y = year + 4800 - a;
    int m = month + 12 * a - 3;
    long days = tm.tm_mday + (153 * m + 2) / 5 + 365L * y + y / 4 - y / 100 + y / 400 - 32045;
    days -= 2440588;  // Julian day of 1970-01-01
    return (time_t)days * 86400 + tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec;
}

}  // namespace


Bytes RandomBytes(size_t count)
{
    Bytes out(count);
    if (count > 0 && RAND_bytes(out.data(), (int)count) != 1)
        out.clear();
    return out;
}


Bytes Sha256(const uint8_t* data, size_t size)
{
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256(data, size, out.data());
    return out;
}


Bytes Sha512(const uint8_t* data, size_t size)
{
    Bytes out(SHA512_DIGEST_LENGTH);
    SHA512(data, size, out.data());
    return out;
}


Bytes Sha512(const std::string& data)
{
    return Sha512((const uint8_t*)data.data(), data.size());
}


bool Ed25519Verify(const Bytes& publicKey, const uint8_t* message, size_t size,
    const Bytes& signature)
{
    if (publicKey.size() != 32 || signature.size() != 64)
        return false;
    PkeyPtr key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, publicKey.data(), 32));
    if (!key)
        return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx != NULL
        && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key.get()) == 1
        && EVP_DigestVerify(ctx, signature.data(), signature.size(), message, size) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}


Bytes Ed25519PublicToX25519(const Bytes& edPublic)
{
    if (edPublic.size() != 32)
        return Bytes();
    // u = (1 + y) / (1 - y) mod p, with y the little-endian encoding minus its
    // sign bit and p = 2^255 - 19.
    std::unique_ptr<BN_CTX, BnCtxDeleter> ctx(BN_CTX_new());
    uint8_t bigEndian[32];
    for (int i = 0; i < 32; i++)
        bigEndian[i] = edPublic[31 - i];
    bigEndian[0] &= 0x7f;
    BnPtr y(BN_bin2bn(bigEndian, 32, NULL));
    BnPtr p(BN_new()), one(BN_new()), numerator(BN_new()), denominator(BN_new()),
        inverse(BN_new()), u(BN_new());
    BN_one(p.get());
    BN_lshift(p.get(), p.get(), 255);
    BN_sub_word(p.get(), 19);
    BN_one(one.get());
    if (!BN_mod_add(numerator.get(), one.get(), y.get(), p.get(), ctx.get())
        || !BN_mod_sub(denominator.get(), one.get(), y.get(), p.get(), ctx.get())
        || BN_mod_inverse(inverse.get(), denominator.get(), p.get(), ctx.get()) == NULL
        || !BN_mod_mul(u.get(), numerator.get(), inverse.get(), p.get(), ctx.get()))
        return Bytes();
    Bytes out(32);
    BN_bn2lebinpad(u.get(), out.data(), 32);
    return out;
}


Bytes X25519PublicFromPrivate(const Bytes& xPrivate)
{
    if (xPrivate.size() != 32)
        return Bytes();
    PkeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, xPrivate.data(), 32));
    if (!key)
        return Bytes();
    Bytes out(32);
    size_t size = 32;
    if (EVP_PKEY_get_raw_public_key(key.get(), out.data(), &size) != 1 || size != 32)
        return Bytes();
    return out;
}


std::string ProtonFingerprint(const Bytes& x25519Public)
{
    return Base64Encode(Sha512(x25519Public.data(), x25519Public.size()));
}


Ed25519Key Ed25519Key::Generate()
{
    Ed25519Key key;
    FromSeed(RandomBytes(32), key);
    return key;
}


bool Ed25519Key::FromSeed(const Bytes& seed, Ed25519Key& key)
{
    if (seed.size() != 32)
        return false;
    PkeyPtr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed.data(), 32));
    if (!pkey)
        return false;
    Bytes pub(32);
    size_t size = 32;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &size) != 1 || size != 32)
        return false;
    key.fSeed = seed;
    key.fPublic = pub;
    return true;
}


std::string Ed25519Key::PrivatePem() const
{
    PkeyPtr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, fSeed.data(), fSeed.size()));
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!pkey || !bio || PEM_write_bio_PrivateKey(bio.get(), pkey.get(), NULL, NULL, 0, NULL, NULL) != 1)
        return std::string();
    return BioString(bio.get());
}


std::string Ed25519Key::PublicPem() const
{
    PkeyPtr pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, fPublic.data(), fPublic.size()));
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!pkey || !bio || PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1)
        return std::string();
    return BioString(bio.get());
}


Bytes Ed25519Key::X25519Private() const
{
    if (!IsValid())
        return Bytes();
    Bytes hash = Sha512(fSeed.data(), fSeed.size());
    hash.resize(32);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    return hash;
}


Bytes Ed25519Key::X25519Public() const
{
    return X25519PublicFromPrivate(X25519Private());
}


bool ParseCertificatePem(const std::string& pem, CertificateInfo& info)
{
    BioPtr bio(BIO_new_mem_buf(pem.data(), (int)pem.size()));
    X509* certificate = bio ? PEM_read_bio_X509(bio.get(), NULL, NULL, NULL) : NULL;
    if (certificate == NULL)
        return false;
    info.notBefore = AsnTime(X509_get0_notBefore(certificate));
    info.notAfter = AsnTime(X509_get0_notAfter(certificate));
    char subject[512];
    X509_NAME_oneline(X509_get_subject_name(certificate), subject, sizeof(subject));
    info.subject = subject;
    info.edPublicKey.clear();
    info.fingerprint.clear();
    EVP_PKEY* key = X509_get0_pubkey(certificate);
    if (key != NULL && EVP_PKEY_id(key) == EVP_PKEY_ED25519) {
        Bytes pub(32);
        size_t size = 32;
        if (EVP_PKEY_get_raw_public_key(key, pub.data(), &size) == 1 && size == 32) {
            info.edPublicKey = pub;
            info.fingerprint = ProtonFingerprint(Ed25519PublicToX25519(pub));
        }
    }
    X509_free(certificate);
    return true;
}

}  // namespace pvpn
