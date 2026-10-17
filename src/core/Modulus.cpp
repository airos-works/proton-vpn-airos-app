#include "Modulus.h"
#include "Crypto.h"
#include <openssl/sha.h>

namespace pvpn {

namespace {

// Primary key of SRP_MODULUS_KEY in python-proton-core's session/api.py.
const uint8_t kModulusKey[32] = {
    0x16, 0xea, 0xd6, 0x5d, 0x7c, 0x23, 0x4d, 0xe9, 0xaa, 0x8c, 0x3e, 0xc2, 0x5e, 0x35, 0xd5, 0xc8,
    0xa7, 0xf4, 0xa1, 0xfe, 0xe7, 0xf4, 0x2b, 0x66, 0x2f, 0xcb, 0xfd, 0x7a, 0x79, 0x33, 0x82, 0x01,
};

const uint8_t kAlgorithmEdDsa = 22;
const uint8_t kHashSha256 = 8;
const uint8_t kHashSha512 = 10;

std::vector<std::string> Lines(const std::string& text)
{
    std::vector<std::string> lines = Split(text, '\n');
    for (std::string& line : lines) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
    }
    return lines;
}

std::string StripTrailingWhitespace(const std::string& line)
{
    size_t end = line.size();
    while (end > 0 && (line[end - 1] == ' ' || line[end - 1] == '\t'))
        end--;
    return line.substr(0, end);
}

// Reads one packet header; returns false if the data is truncated.
bool ReadPacket(const Bytes& data, size_t& offset, int& tag, Bytes& body)
{
    if (offset >= data.size() || !(data[offset] & 0x80))
        return false;
    uint8_t header = data[offset++];
    size_t length = 0;
    if (header & 0x40) {
        tag = header & 0x3f;
        if (offset >= data.size())
            return false;
        uint8_t first = data[offset++];
        if (first < 192) {
            length = first;
        } else if (first < 224) {
            if (offset >= data.size())
                return false;
            length = ((first - 192) << 8) + data[offset++] + 192;
        } else if (first == 255) {
            if (offset + 4 > data.size())
                return false;
            length = (size_t)data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8
                | data[offset + 3];
            offset += 4;
        } else {
            return false;  // partial lengths are not used by signatures
        }
    } else {
        tag = (header >> 2) & 0xf;
        int lengthType = header & 3;
        int bytes = lengthType == 0 ? 1 : lengthType == 1 ? 2 : lengthType == 2 ? 4 : 0;
        if (bytes == 0 || offset + bytes > data.size())
            return false;
        for (int i = 0; i < bytes; i++)
            length = length << 8 | data[offset++];
    }
    if (offset + length > data.size())
        return false;
    body.assign(data.begin() + offset, data.begin() + offset + length);
    offset += length;
    return true;
}

// An MPI as a fixed-size big-endian value.
bool ReadMpi(const Bytes& data, size_t& offset, size_t size, Bytes& out)
{
    if (offset + 2 > data.size())
        return false;
    size_t bits = data[offset] << 8 | data[offset + 1];
    size_t bytes = (bits + 7) / 8;
    offset += 2;
    if (offset + bytes > data.size() || bytes > size)
        return false;
    out.assign(size - bytes, 0);
    out.insert(out.end(), data.begin() + offset, data.begin() + offset + bytes);
    offset += bytes;
    return true;
}

}  // namespace


const Bytes& ModulusSigningKey()
{
    static const Bytes key(kModulusKey, kModulusKey + sizeof(kModulusKey));
    return key;
}


bool VerifyCleartextSignature(const std::string& armored, const Bytes& edPublicKey,
    std::string& text, std::string& error)
{
    std::vector<std::string> lines = Lines(armored);
    size_t i = 0;
    while (i < lines.size() && lines[i] != "-----BEGIN PGP SIGNED MESSAGE-----")
        i++;
    if (i == lines.size()) {
        error = "not a signed message";
        return false;
    }
    i++;
    // Armor headers ("Hash: SHA256") up to an empty line.
    while (i < lines.size() && !lines[i].empty())
        i++;
    i++;
    std::vector<std::string> body;
    while (i < lines.size() && lines[i] != "-----BEGIN PGP SIGNATURE-----") {
        std::string line = lines[i++];
        if (StartsWith(line, "- "))
            line = line.substr(2);
        body.push_back(line);
    }
    if (i == lines.size()) {
        error = "no signature";
        return false;
    }
    i++;
    while (i < lines.size() && !lines[i].empty())
        i++;
    i++;
    std::string base64;
    while (i < lines.size() && lines[i] != "-----END PGP SIGNATURE-----") {
        if (!StartsWith(lines[i], "="))  // the CRC-24 line
            base64 += lines[i];
        i++;
    }
    Bytes packets;
    if (!Base64Decode(base64, packets) || packets.empty()) {
        error = "bad signature encoding";
        return false;
    }

    // Canonical text: CRLF line endings, trailing whitespace removed, and no
    // line ending after the last line.
    std::string canonical;
    for (size_t line = 0; line < body.size(); line++) {
        if (line > 0)
            canonical += "\r\n";
        canonical += StripTrailingWhitespace(body[line]);
    }

    size_t offset = 0;
    int tag = 0;
    Bytes signature;
    if (!ReadPacket(packets, offset, tag, signature) || tag != 2) {
        error = "no signature packet";
        return false;
    }
    if (signature.size() < 6 || signature[0] != 4 || signature[1] != 0x01
        || signature[2] != kAlgorithmEdDsa) {
        error = "unsupported signature";
        return false;
    }
    uint8_t hashAlgorithm = signature[3];
    size_t hashedLength = signature[4] << 8 | signature[5];
    size_t hashedEnd = 6 + hashedLength;
    if (hashedEnd + 2 > signature.size()) {
        error = "truncated signature";
        return false;
    }
    size_t unhashedLength = signature[hashedEnd] << 8 | signature[hashedEnd + 1];
    size_t position = hashedEnd + 2 + unhashedLength;
    if (position + 2 > signature.size()) {
        error = "truncated signature";
        return false;
    }
    uint8_t prefix[2] = {signature[position], signature[position + 1]};
    position += 2;
    Bytes r, s;
    if (!ReadMpi(signature, position, 32, r) || !ReadMpi(signature, position, 32, s)) {
        error = "bad signature values";
        return false;
    }

    Bytes hashInput(canonical.begin(), canonical.end());
    hashInput.insert(hashInput.end(), signature.begin(), signature.begin() + hashedEnd);
    hashInput.push_back(0x04);
    hashInput.push_back(0xff);
    for (int shift = 24; shift >= 0; shift -= 8)
        hashInput.push_back((hashedEnd >> shift) & 0xff);
    Bytes digest;
    if (hashAlgorithm == kHashSha256)
        digest = Sha256(hashInput.data(), hashInput.size());
    else if (hashAlgorithm == kHashSha512)
        digest = Sha512(hashInput.data(), hashInput.size());
    else {
        error = "unsupported hash";
        return false;
    }
    if (digest[0] != prefix[0] || digest[1] != prefix[1]) {
        error = "hash mismatch";
        return false;
    }
    Bytes edSignature = r;
    edSignature.insert(edSignature.end(), s.begin(), s.end());
    if (!Ed25519Verify(edPublicKey, digest.data(), digest.size(), edSignature)) {
        error = "invalid signature";
        return false;
    }
    text.clear();
    for (size_t line = 0; line < body.size(); line++) {
        if (line > 0)
            text += "\n";
        text += body[line];
    }
    return true;
}


bool VerifyModulus(const std::string& armored, Bytes& modulus, std::string& error)
{
    std::string text;
    if (!VerifyCleartextSignature(armored, ModulusSigningKey(), text, error))
        return false;
    if (!Base64Decode(Trim(text), modulus) || modulus.size() != 256) {
        error = "bad modulus";
        return false;
    }
    return true;
}

}  // namespace pvpn
