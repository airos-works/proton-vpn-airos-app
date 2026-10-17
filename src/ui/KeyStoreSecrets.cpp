#include "KeyStoreSecrets.h"
#include <Key.h>
#include <KeyStore.h>

namespace {

const char kKeyring[] = "Proton VPN";
const char kIdentifier[] = "Proton VPN";
const char kSecondary[] = "session";

bool EnsureKeyring(BKeyStore& store)
{
    // AddKeyring fails with B_NAME_IN_USE when it exists already.
    status_t status = store.AddKeyring(kKeyring);
    return status == B_OK || status == B_NAME_IN_USE;
}

}  // namespace


KeyStoreSecrets::KeyStoreSecrets(const std::string& fallbackPath)
    :
    fFallback(fallbackPath)
{
}


bool KeyStoreSecrets::Load(std::string& data)
{
    BKeyStore store;
    BPasswordKey key;
    if (store.GetKey(kKeyring, B_KEY_TYPE_PASSWORD, kIdentifier, kSecondary, false, key) == B_OK) {
        data = key.Password();
        return !data.empty();
    }
    return fFallback.Load(data);
}


bool KeyStoreSecrets::Save(const std::string& data)
{
    BKeyStore store;
    if (EnsureKeyring(store)) {
        BPasswordKey old;
        if (store.GetKey(kKeyring, B_KEY_TYPE_PASSWORD, kIdentifier, kSecondary, false, old) == B_OK)
            store.RemoveKey(kKeyring, old);
        BPasswordKey key(data.c_str(), B_KEY_PURPOSE_GENERIC, kIdentifier, kSecondary);
        if (store.AddKey(kKeyring, key) == B_OK) {
            fFallback.Remove();
            return true;
        }
    }
    return fFallback.Save(data);
}


void KeyStoreSecrets::Remove()
{
    BKeyStore store;
    BPasswordKey key;
    if (store.GetKey(kKeyring, B_KEY_TYPE_PASSWORD, kIdentifier, kSecondary, false, key) == B_OK)
        store.RemoveKey(kKeyring, key);
    fFallback.Remove();
}
