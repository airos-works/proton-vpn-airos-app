// Small helpers shared by the core: Base64, hex, string and time utilities.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace pvpn {

typedef std::vector<uint8_t> Bytes;

std::string Base64Encode(const uint8_t* data, size_t size);
std::string Base64Encode(const Bytes& data);
std::string Base64Encode(const std::string& data);
// Ignores whitespace; returns false on any other invalid character.
bool Base64Decode(const std::string& text, Bytes& out);
Bytes Base64Decode(const std::string& text);

std::string HexEncode(const uint8_t* data, size_t size);
std::string HexEncode(const Bytes& data);

std::string Trim(const std::string& text);
std::string ToUpper(std::string text);
std::string ToLower(std::string text);
bool StartsWith(const std::string& text, const std::string& prefix);
bool EndsWith(const std::string& text, const std::string& suffix);
std::vector<std::string> Split(const std::string& text, char separator);
std::string Join(const std::vector<std::string>& parts, const std::string& separator);
// Case- and accent-insensitive "contains", for searching names such as
// "Zürich" with "zur". Only Latin-1 and common Latin Extended-A letters are folded.
bool FoldedContains(const std::string& haystack, const std::string& needle);
std::string FoldForSearch(const std::string& text);

// Seconds since the epoch, as a double, and a monotonic clock in seconds.
double Now();
double MonotonicNow();

// Random number in [0, 1) from the system's CSPRNG, for jitter.
double RandomUnit();
// 1 +/- spread * random, as Proton's refresh intervals use.
double Jitter(double spread);

bool ReadFile(const std::string& path, std::string& contents);
// Writes atomically (temporary file + rename) with the given mode.
bool WriteFile(const std::string& path, const std::string& contents, int mode = 0600);
bool MakeDirectories(const std::string& path, int mode = 0700);

// Natural ordering for server names such as "CH#2" < "CH#10".
bool NaturalLess(const std::string& a, const std::string& b);

}  // namespace pvpn
