// English country names for the two-letter codes the API uses.
#pragma once
#include <string>

namespace pvpn {

// The name for a code such as "CH"; the code itself if it is unknown.
std::string CountryName(const std::string& code);
// The code for an English name, or an empty string.
std::string CountryCodeForName(const std::string& name);
bool IsCountryCode(const std::string& code);

}  // namespace pvpn
