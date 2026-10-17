#include "Util.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pvpn {

namespace {

const char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64Value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

// Folds one UTF-8 encoded code point to lower-case ASCII where it has an
// obvious base letter; returns the number of bytes consumed.
size_t FoldOne(const std::string& text, size_t i, std::string& out)
{
    unsigned char c = text[i];
    if (c < 0x80) {
        out += (char)tolower(c);
        return 1;
    }
    if ((c & 0xe0) == 0xc0 && i + 1 < text.size()) {
        unsigned code = ((c & 0x1f) << 6) | (text[i + 1] & 0x3f);
        static const struct { unsigned from, to; const char* base; } kRanges[] = {
            {0xc0, 0xc5, "a"}, {0xc6, 0xc6, "ae"}, {0xc7, 0xc7, "c"}, {0xc8, 0xcb, "e"},
            {0xcc, 0xcf, "i"}, {0xd0, 0xd0, "d"}, {0xd1, 0xd1, "n"}, {0xd2, 0xd6, "o"},
            {0xd8, 0xd8, "o"}, {0xd9, 0xdc, "u"}, {0xdd, 0xdd, "y"}, {0xdf, 0xdf, "ss"},
            {0xe0, 0xe5, "a"}, {0xe6, 0xe6, "ae"}, {0xe7, 0xe7, "c"}, {0xe8, 0xeb, "e"},
            {0xec, 0xef, "i"}, {0xf0, 0xf0, "d"}, {0xf1, 0xf1, "n"}, {0xf2, 0xf6, "o"},
            {0xf8, 0xf8, "o"}, {0xf9, 0xfc, "u"}, {0xfd, 0xfd, "y"}, {0xff, 0xff, "y"},
            {0x100, 0x105, "a"}, {0x106, 0x10d, "c"}, {0x10e, 0x111, "d"}, {0x112, 0x11b, "e"},
            {0x11c, 0x123, "g"}, {0x124, 0x127, "h"}, {0x128, 0x131, "i"}, {0x134, 0x135, "j"},
            {0x136, 0x138, "k"}, {0x139, 0x142, "l"}, {0x143, 0x14b, "n"}, {0x14c, 0x151, "o"},
            {0x152, 0x153, "oe"}, {0x154, 0x159, "r"}, {0x15a, 0x161, "s"}, {0x162, 0x167, "t"},
            {0x168, 0x173, "u"}, {0x174, 0x175, "w"}, {0x176, 0x178, "y"}, {0x179, 0x17e, "z"},
            {0x218, 0x219, "s"}, {0x21a, 0x21b, "t"},
        };
        for (const auto& range : kRanges) {
            if (code >= range.from && code <= range.to) {
                out += range.base;
                return 2;
            }
        }
        out.append(text, i, 2);
        return 2;
    }
    size_t length = (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 1;
    out.append(text, i, std::min(length, text.size() - i));
    return length;
}

}  // namespace


std::string Base64Encode(const uint8_t* data, size_t size)
{
    std::string out;
    out.reserve((size + 2) / 3 * 4);
    for (size_t i = 0; i < size; i += 3) {
        uint32_t chunk = data[i] << 16;
        if (i + 1 < size)
            chunk |= data[i + 1] << 8;
        if (i + 2 < size)
            chunk |= data[i + 2];
        out += kBase64[(chunk >> 18) & 63];
        out += kBase64[(chunk >> 12) & 63];
        out += i + 1 < size ? kBase64[(chunk >> 6) & 63] : '=';
        out += i + 2 < size ? kBase64[chunk & 63] : '=';
    }
    return out;
}


std::string Base64Encode(const Bytes& data)
{
    return Base64Encode(data.data(), data.size());
}


std::string Base64Encode(const std::string& data)
{
    return Base64Encode((const uint8_t*)data.data(), data.size());
}


bool Base64Decode(const std::string& text, Bytes& out)
{
    out.clear();
    uint32_t chunk = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || isspace((unsigned char)c))
            continue;
        int value = Base64Value(c);
        if (value < 0)
            return false;
        chunk = (chunk << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((chunk >> bits) & 0xff);
        }
    }
    return true;
}


Bytes Base64Decode(const std::string& text)
{
    Bytes out;
    if (!Base64Decode(text, out))
        out.clear();
    return out;
}


std::string HexEncode(const uint8_t* data, size_t size)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; i++) {
        out += kHex[data[i] >> 4];
        out += kHex[data[i] & 15];
    }
    return out;
}


std::string HexEncode(const Bytes& data)
{
    return HexEncode(data.data(), data.size());
}


std::string Trim(const std::string& text)
{
    size_t start = 0;
    while (start < text.size() && isspace((unsigned char)text[start]))
        start++;
    size_t end = text.size();
    while (end > start && isspace((unsigned char)text[end - 1]))
        end--;
    return text.substr(start, end - start);
}


std::string ToUpper(std::string text)
{
    for (char& c : text)
        c = toupper((unsigned char)c);
    return text;
}


std::string ToLower(std::string text)
{
    for (char& c : text)
        c = tolower((unsigned char)c);
    return text;
}


bool StartsWith(const std::string& text, const std::string& prefix)
{
    return text.compare(0, prefix.size(), prefix) == 0;
}


bool EndsWith(const std::string& text, const std::string& suffix)
{
    return text.size() >= suffix.size()
        && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}


std::vector<std::string> Split(const std::string& text, char separator)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t end = text.find(separator, start);
        parts.push_back(text.substr(start, end - start));
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return parts;
}


std::string Join(const std::vector<std::string>& parts, const std::string& separator)
{
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i > 0)
            out += separator;
        out += parts[i];
    }
    return out;
}


std::string FoldForSearch(const std::string& text)
{
    std::string out;
    for (size_t i = 0; i < text.size();)
        i += FoldOne(text, i, out);
    return out;
}


bool FoldedContains(const std::string& haystack, const std::string& needle)
{
    return FoldForSearch(haystack).find(FoldForSearch(needle)) != std::string::npos;
}


double Now()
{
    using namespace std::chrono;
    return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}


double MonotonicNow()
{
    using namespace std::chrono;
    return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}


double RandomUnit()
{
    uint64_t value = 0;
    if (RAND_bytes((unsigned char*)&value, sizeof(value)) != 1)
        value = (uint64_t)rand() << 32 | rand();
    return (value >> 11) * (1.0 / 9007199254740992.0);
}


double Jitter(double spread)
{
    return 1 + spread * (2 * RandomUnit() - 1);
}


bool ReadFile(const std::string& path, std::string& contents)
{
    FILE* file = fopen(path.c_str(), "rb");
    if (file == NULL)
        return false;
    contents.clear();
    char buffer[8192];
    size_t got;
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
        contents.append(buffer, got);
    bool ok = !ferror(file);
    fclose(file);
    return ok;
}


bool WriteFile(const std::string& path, const std::string& contents, int mode)
{
    std::string temporary = path + ".new";
    int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return false;
    fchmod(fd, mode);
    size_t written = 0;
    while (written < contents.size()) {
        ssize_t result = write(fd, contents.data() + written, contents.size() - written);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(temporary.c_str());
            return false;
        }
        written += result;
    }
    fsync(fd);
    close(fd);
    if (rename(temporary.c_str(), path.c_str()) != 0) {
        unlink(temporary.c_str());
        return false;
    }
    return true;
}


bool MakeDirectories(const std::string& path, int mode)
{
    if (path.empty())
        return false;
    std::string partial;
    for (const std::string& part : Split(path, '/')) {
        partial += part;
        if (!partial.empty() && mkdir(partial.c_str(), mode) != 0 && errno != EEXIST)
            return false;
        partial += '/';
    }
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}


bool NaturalLess(const std::string& a, const std::string& b)
{
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        if (isdigit((unsigned char)a[i]) && isdigit((unsigned char)b[j])) {
            size_t endA = i, endB = j;
            while (endA < a.size() && isdigit((unsigned char)a[endA]))
                endA++;
            while (endB < b.size() && isdigit((unsigned char)b[endB]))
                endB++;
            unsigned long long numberA = strtoull(a.substr(i, endA - i).c_str(), NULL, 10);
            unsigned long long numberB = strtoull(b.substr(j, endB - j).c_str(), NULL, 10);
            if (numberA != numberB)
                return numberA < numberB;
            i = endA;
            j = endB;
            continue;
        }
        char ca = tolower((unsigned char)a[i]), cb = tolower((unsigned char)b[j]);
        if (ca != cb)
            return ca < cb;
        i++;
        j++;
    }
    return a.size() - i < b.size() - j;
}

}  // namespace pvpn
