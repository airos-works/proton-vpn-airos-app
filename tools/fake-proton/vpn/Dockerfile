# Fake ProtonVPN server (and, for the self-test, its throwaway clients).
# Build with --network host on hosts whose bridge containers have no egress:
#   docker build --network host -t fake-proton-vpn tools/fake-proton/vpn
FROM alpine:3.20
RUN apk add --no-cache openvpn wireguard-tools-wg iproute2 iptables dnsmasq \
        python3 py3-cryptography tini
COPY proton-tls-crypt.key entrypoint.sh set-peer.sh services.py /opt/fake-proton/
RUN chmod 0755 /opt/fake-proton/entrypoint.sh /opt/fake-proton/set-peer.sh \
    && chmod 0600 /opt/fake-proton/proton-tls-crypt.key
EXPOSE 1194/udp 443/tcp 51820/udp
ENTRYPOINT ["/sbin/tini", "-g", "--"]
CMD ["/opt/fake-proton/entrypoint.sh"]
