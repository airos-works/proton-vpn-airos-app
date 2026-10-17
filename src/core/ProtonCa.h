// Proton's built-in certificate authorities. For tests against a stand-in
// server, PROTON_VPN_OPENVPN_CA_FILE and PROTON_VPN_AGENT_CA_FILE replace them.
#pragma once
#include <string>

namespace pvpn {

std::string OpenVpnCaPem();
std::string LocalAgentCaPem();

}  // namespace pvpn
