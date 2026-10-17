// The session tokens and VPN account (with the client's private key) in
// Haiku's key store, as the Linux app keeps them in the keyring. A mode-600
// file is the fallback when the key store is not available.
#pragma once
#include "core/Client.h"
#include <string>

class KeyStoreSecrets : public pvpn::SecretStore {
public:
    explicit KeyStoreSecrets(const std::string& fallbackPath);

    bool Load(std::string& data) override;
    bool Save(const std::string& data) override;
    void Remove() override;

private:
    pvpn::FileSecretStore fFallback;
};
