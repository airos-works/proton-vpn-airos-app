// Checks the SRP modulus the API sends with /auth/info. It arrives as an OpenPGP
// cleartext-signed message signed by Proton's fixed modulus key
// (fingerprint 248097092b458509c508dac0350585c4e9518f26); python-proton-core
// checks it with GnuPG. This is a minimal verifier for exactly that format:
// one v4 EdDSA signature of type 0x01 over canonical text.
#pragma once
#include "Util.h"
#include <string>

namespace pvpn {

// Returns false (with a reason in error) unless the signature is valid; on
// success modulus holds the decoded 256-byte modulus.
bool VerifyModulus(const std::string& armored, Bytes& modulus, std::string& error);

// The same check against another key, for tests.
bool VerifyCleartextSignature(const std::string& armored, const Bytes& edPublicKey,
    std::string& text, std::string& error);

// Proton's modulus key (the Ed25519 point of the primary key).
const Bytes& ModulusSigningKey();

}  // namespace pvpn
