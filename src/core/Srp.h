// Proton's SRP-6a client (auth version 3 and 4), a port of
// proton/session/srp/_pysrp.py: 2048-bit modulus, g = 2, numbers encoded
// little-endian in 256 bytes, H = "PMHash" (four SHA-512s), and the password
// hashed with bcrypt ($2y$, cost 10) over the salt + "proton".
#pragma once
#include "Util.h"
#include <string>

namespace pvpn {

// SHA-512(data || 0) || SHA-512(data || 1) || SHA-512(data || 2) || SHA-512(data || 3)
Bytes PmHash(const Bytes& data);
// The x of SRP before reduction: PMHash(bcrypt(password, salt) || modulus).
// Returns an empty vector for unsupported versions or bcrypt errors.
Bytes HashPassword(const std::string& password, const Bytes& salt, const Bytes& modulus,
    int version);
// The bcrypt step alone, the 60-character "$2y$10$..." string.
std::string ProtonBcrypt(const std::string& password, const Bytes& salt);

class SrpClient {
public:
    // modulus: 256 bytes, little-endian, already signature-checked.
    SrpClient(const std::string& password, const Bytes& modulus);
    ~SrpClient();

    // For tests: a fixed 32-byte secret ephemeral (little-endian).
    void SetSecretEphemeral(const Bytes& a);

    // The public ephemeral A, 256 bytes.
    Bytes Challenge();
    // Computes the client proof M from the server's salt and ephemeral B.
    // Returns false if the server's values fail the SRP-6a safety checks.
    bool ProcessChallenge(const Bytes& salt, const Bytes& serverEphemeral, int version,
        Bytes& clientProof);
    bool VerifyServerProof(const Bytes& serverProof) const;
    const Bytes& SessionKey() const { return fSessionKey; }

private:
    struct Numbers;
    Numbers* fNumbers;
    std::string fPassword;
    Bytes fModulus;
    Bytes fExpectedServerProof;
    Bytes fSessionKey;
};

}  // namespace pvpn
