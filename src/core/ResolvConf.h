// Puts a VPN's name servers into Haiku's resolv.conf and takes them out again.
//
// net_server rewrites resolv.conf on every DHCP renewal. It keeps what stands
// above a "# Dynamic DNS entries" line and replaces what follows it, so the
// VPN block goes above that marker (added when missing, removed with the block).
#pragma once
#include <string>
#include <vector>

namespace pvpn {

extern const char* const kResolvConfPath;   // /boot/system/settings/network/resolv.conf

std::string AddVpnDns(const std::string& content, const std::vector<std::string>& servers,
    const std::vector<std::string>& domains, const std::string& owner);
std::string RemoveVpnDns(const std::string& content);
bool HasVpnDns(const std::string& content);

// File versions; they return false (and leave the file alone) on I/O errors.
bool ApplyVpnDns(const std::string& path, const std::vector<std::string>& servers,
    const std::vector<std::string>& domains, const std::string& owner);
bool RestoreDns(const std::string& path);

}  // namespace pvpn
