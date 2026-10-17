# Sourced in the test VM: environment for testing against tools/fake-proton
# (copy to /Data/fakeenv.sh in the guest).
mkdir -p /Data/fake && cd /Data/fake
for f in api-ca.pem openvpn-ca.pem agent-ca.pem; do curl -s -o $f http://10.0.2.2:18080/fake/files/$f; done
export PROTON_VPN_API_URL=http://10.0.2.2:18080 PROTON_VPN_API_PINS=none
export PROTON_VPN_OPENVPN_CA_FILE=/Data/fake/openvpn-ca.pem PROTON_VPN_AGENT_CA_FILE=/Data/fake/agent-ca.pem
export PROTON_VPN_OPENVPN=/Data/proton-vpn/build-haiku/openvpn/proton-openvpn
CLI="/Data/proton-vpn/build-haiku/proton-vpn-cli --state /Data/fake/state"
