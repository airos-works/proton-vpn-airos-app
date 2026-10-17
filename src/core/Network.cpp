#include "Network.h"
#include "Util.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__HAIKU__)
#include <net/route.h>
#include <sys/sockio.h>
#else
#include <linux/if_tun.h>
#include <sys/wait.h>
#endif

namespace pvpn {

bool ParseCidr(const std::string& text, std::string& address, int& prefix)
{
    size_t slash = text.find('/');
    address = text.substr(0, slash);
    bool v6 = address.find(':') != std::string::npos;
    prefix = v6 ? 128 : 32;
    if (slash != std::string::npos)
        prefix = atoi(text.c_str() + slash + 1);
    uint8_t buffer[16];
    return inet_pton(v6 ? AF_INET6 : AF_INET, address.c_str(), buffer) == 1
        && prefix >= 0 && prefix <= (v6 ? 128 : 32);
}


bool HasDefaultRoute()
{
    Route route;
    return FindDefaultRoute(route) || FindDefaultRoute6(route);
}


#if defined(__HAIKU__)

namespace {

const int kTunnelUnits = 10;

bool FillAddress(int family, const std::string& text, sockaddr_storage& storage)
{
    memset(&storage, 0, sizeof(storage));
    if (family == AF_INET) {
        sockaddr_in& address = (sockaddr_in&)storage;
        address.sin_len = sizeof(sockaddr_in);
        address.sin_family = AF_INET;
        return inet_pton(AF_INET, text.c_str(), &address.sin_addr) == 1;
    }
    sockaddr_in6& address = (sockaddr_in6&)storage;
    address.sin6_len = sizeof(sockaddr_in6);
    address.sin6_family = AF_INET6;
    return inet_pton(AF_INET6, text.c_str(), &address.sin6_addr) == 1;
}

void FillMask(int family, int prefix, sockaddr_storage& storage)
{
    memset(&storage, 0, sizeof(storage));
    if (family == AF_INET) {
        sockaddr_in& mask = (sockaddr_in&)storage;
        mask.sin_len = sizeof(sockaddr_in);
        mask.sin_family = AF_INET;
        mask.sin_addr.s_addr = prefix == 0 ? 0 : htonl(0xffffffffu << (32 - prefix));
        return;
    }
    sockaddr_in6& mask = (sockaddr_in6&)storage;
    mask.sin6_len = sizeof(sockaddr_in6);
    mask.sin6_family = AF_INET6;
    for (int i = 0; i < prefix && i < 128; i++)
        mask.sin6_addr.s6_addr[i / 8] |= 0x80 >> (i % 8);
}

int PrefixOf(const sockaddr* mask)
{
    if (mask == NULL)
        return 0;
    const uint8_t* bytes;
    size_t size;
    if (mask->sa_family == AF_INET6) {
        bytes = ((const sockaddr_in6*)mask)->sin6_addr.s6_addr;
        size = 16;
    } else {
        bytes = (const uint8_t*)&((const sockaddr_in*)mask)->sin_addr;
        size = 4;
    }
    int prefix = 0;
    for (size_t i = 0; i < size; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if (bytes[i] & (1 << bit))
                prefix++;
            else
                return prefix;
        }
    }
    return prefix;
}

std::string AddressText(const sockaddr* address)
{
    char text[INET6_ADDRSTRLEN] = "";
    if (address == NULL)
        return "";
    if (address->sa_family == AF_INET)
        inet_ntop(AF_INET, &((const sockaddr_in*)address)->sin_addr, text, sizeof(text));
    else if (address->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &((const sockaddr_in6*)address)->sin6_addr, text, sizeof(text));
    return text;
}

bool RouteIoctl(bool add, const Route& route, std::string& error)
{
    int family = route.destination.find(':') != std::string::npos
        || route.gateway.find(':') != std::string::npos ? AF_INET6 : AF_INET;
    sockaddr_storage destination, mask, gateway;
    if (!route.isDefault && !FillAddress(family, route.destination, destination)) {
        error = "bad route destination " + route.destination;
        return false;
    }
    FillMask(family, route.prefix, mask);
    bool hasGateway = !route.gateway.empty();
    if (hasGateway && !FillAddress(family, route.gateway, gateway)) {
        error = "bad route gateway " + route.gateway;
        return false;
    }
    route_entry entry;
    memset(&entry, 0, sizeof(entry));
    if (route.isDefault) {
        entry.flags = RTF_DEFAULT;
    } else {
        entry.destination = (sockaddr*)&destination;
        entry.mask = (sockaddr*)&mask;
    }
    if (hasGateway) {
        entry.gateway = (sockaddr*)&gateway;
        entry.flags |= RTF_GATEWAY;
    }
    if (add)
        entry.flags |= RTF_STATIC;
    ifreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifr_name, route.interface.c_str(), sizeof(request.ifr_name));
    request.ifr_route = entry;
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = strerror(errno);
        return false;
    }
    bool ok = ioctl(fd, add ? SIOCADDRT : SIOCDELRT, &request, sizeof(request)) == 0;
    if (!ok)
        error = std::string(add ? "adding" : "deleting") + " route " + route.destination + "/"
            + std::to_string(route.prefix) + " on " + route.interface + ": " + strerror(errno);
    close(fd);
    return ok;
}

}  // namespace


bool ListRoutes(std::vector<Route>& routes, int family)
{
    routes.clear();
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;
    ifconf config;
    config.ifc_len = sizeof(config.ifc_value);
    if (ioctl(fd, SIOCGRTSIZE, &config, sizeof(config)) < 0) {
        close(fd);
        return false;
    }
    int size = config.ifc_value;
    if (size <= 0) {
        close(fd);
        return true;
    }
    std::vector<uint8_t> buffer(size);
    config.ifc_len = size;
    config.ifc_buf = buffer.data();
    if (ioctl(fd, SIOCGRTTABLE, &config, sizeof(config)) < 0) {
        close(fd);
        return false;
    }
    close(fd);
    uint8_t* position = buffer.data();
    uint8_t* end = position + config.ifc_len;
    while (position + IF_NAMESIZE + sizeof(route_entry) <= end) {
        ifreq* interface = (ifreq*)position;
        route_entry& entry = interface->ifr_route;
        Route route;
        route.interface = interface->ifr_name;
        route.isDefault = (entry.flags & RTF_DEFAULT) != 0;
        route.destination = AddressText(entry.destination);
        route.prefix = PrefixOf(entry.mask);
        if ((entry.flags & RTF_GATEWAY) != 0)
            route.gateway = AddressText(entry.gateway);
        routes.push_back(route);
        size_t addresses = 0;
        if (entry.destination != NULL)
            addresses += entry.destination->sa_len;
        if (entry.mask != NULL)
            addresses += entry.mask->sa_len;
        if (entry.gateway != NULL)
            addresses += entry.gateway->sa_len;
        position += IF_NAMESIZE + sizeof(route_entry) + addresses;
    }
    return true;
}


static bool FindDefault(Route& route, int family)
{
    std::vector<Route> routes;
    if (!ListRoutes(routes, family))
        return false;
    for (const Route& candidate : routes) {
        if (candidate.isDefault && !candidate.gateway.empty()
            && !StartsWith(candidate.interface, "tun/")) {
            route = candidate;
            return true;
        }
    }
    return false;
}


bool FindDefaultRoute(Route& route)
{
    return FindDefault(route, AF_INET);
}


bool FindDefaultRoute6(Route& route)
{
    return FindDefault(route, AF_INET6);
}


bool AddRoute(const Route& route, std::string& error)
{
    return RouteIoctl(true, route, error);
}


bool DeleteRoute(const Route& route, std::string& error)
{
    return RouteIoctl(false, route, error);
}


TunDevice::TunDevice()
{
}


TunDevice::~TunDevice()
{
    Close();
}


bool TunDevice::Open(std::string& error)
{
    for (int i = 0; i < kTunnelUnits; i++) {
        std::string name = "tun/" + std::to_string(i);
        std::string path = "/dev/" + name;
        bool created = false;
        if (access(path.c_str(), F_OK) != 0) {
            // Adding the interface makes the driver publish /dev/tun/<n>.
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0)
                continue;
            ifaliasreq request;
            memset(&request, 0, sizeof(request));
            strlcpy(request.ifra_name, name.c_str(), sizeof(request.ifra_name));
            bool ok = ioctl(fd, SIOCAIFADDR, &request, sizeof(request)) == 0;
            close(fd);
            if (!ok)
                continue;
            created = true;
        } else if (if_nametoindex(name.c_str()) == 0) {
            // The interface is gone, but the stack keeps the unit while
            // sockets that used its address linger (TCP TIME_WAIT).
            continue;
        }
        int fd = open(path.c_str(), O_RDWR);
        if (fd < 0) {
            if (created) {
                fName = name;
                fCreated = true;
                Close();
            }
            continue;   // another tunnel owns it
        }
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        fFd = fd;
        fName = name;
        fCreated = created;
        return true;
    }
    error = "no free tunnel device (tun/0 to tun/9)";
    return false;
}


void TunDevice::Close()
{
    if (fFd >= 0) {
        close(fFd);
        fFd = -1;
    }
    if (fCreated && !fName.empty()) {
        // The driver refuses to remove a unit that is still open.
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            ifreq request;
            memset(&request, 0, sizeof(request));
            strlcpy(request.ifr_name, fName.c_str(), sizeof(request.ifr_name));
            request.ifr_addr.sa_family = AF_UNSPEC;
            ioctl(fd, SIOCDIFADDR, &request, sizeof(request));
            close(fd);
        }
    }
    fCreated = false;
    fName.clear();
}


bool TunDevice::SetAddress(const std::string& address, int prefix, const std::string& peer,
    std::string& error)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = strerror(errno);
        return false;
    }
    ifaliasreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifra_name, fName.c_str(), sizeof(request.ifra_name));
    // ifra_index -1: replace the first (here: the empty) address.
    request.ifra_index = -1;
    bool ok = FillAddress(AF_INET, address, request.ifra_addr);
    FillMask(AF_INET, prefix, request.ifra_mask);
    if (ok && !peer.empty())
        ok = FillAddress(AF_INET, peer, request.ifra_destination);
    if (ok)
        ok = ioctl(fd, B_SOCKET_SET_ALIAS, &request, sizeof(request)) == 0
            || ioctl(fd, SIOCAIFADDR, &request, sizeof(request)) == 0;
    if (!ok)
        error = "setting " + address + " on " + fName + ": " + strerror(errno);
    close(fd);
    return ok;
}


bool TunDevice::SetAddress6(const std::string& address, int prefix, std::string& error)
{
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = strerror(errno);
        return false;
    }
    ifaliasreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifra_name, fName.c_str(), sizeof(request.ifra_name));
    request.ifra_index = -1;
    bool ok = FillAddress(AF_INET6, address, request.ifra_addr);
    FillMask(AF_INET6, prefix, request.ifra_mask);
    if (ok)
        ok = ioctl(fd, SIOCAIFADDR, &request, sizeof(request)) == 0;
    if (!ok)
        error = "setting " + address + " on " + fName + ": " + strerror(errno);
    close(fd);
    return ok;
}


bool TunDevice::SetMtu(int mtu, std::string& error)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = strerror(errno);
        return false;
    }
    ifreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifr_name, fName.c_str(), sizeof(request.ifr_name));
    request.ifr_mtu = mtu;
    bool ok = ioctl(fd, SIOCSIFMTU, &request, sizeof(request)) == 0;
    if (!ok)
        error = "setting the MTU of " + fName + ": " + strerror(errno);
    close(fd);
    return ok;
}


bool TunDevice::Up(std::string& error)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = strerror(errno);
        return false;
    }
    ifreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifr_name, fName.c_str(), sizeof(request.ifr_name));
    bool ok = ioctl(fd, SIOCGIFFLAGS, &request, sizeof(request)) == 0;
    if (ok) {
        request.ifr_flags |= IFF_UP;
        ok = ioctl(fd, SIOCSIFFLAGS, &request, sizeof(request)) == 0;
    }
    if (!ok)
        error = "bringing " + fName + " up: " + strerror(errno);
    close(fd);
    return ok;
}

#else  // Linux, for tests

namespace {

bool Run(const std::vector<std::string>& args, std::string& error)
{
    std::string command;
    for (const std::string& arg : args)
        command += (command.empty() ? "" : " ") + std::string("'") + arg + "'";
    int status = system((command + " 2>/dev/null").c_str());
    if (status != 0) {
        error = command + " failed";
        return false;
    }
    return true;
}

std::string RouteSpec(const Route& route)
{
    return route.isDefault ? "default" : route.destination + "/" + std::to_string(route.prefix);
}

}  // namespace


bool ListRoutes(std::vector<Route>& routes, int family)
{
    routes.clear();
    FILE* pipe = popen(family == AF_INET6 ? "ip -6 route show 2>/dev/null"
        : "ip -4 route show 2>/dev/null", "r");
    if (pipe == NULL)
        return false;
    char line[512];
    while (fgets(line, sizeof(line), pipe) != NULL) {
        std::vector<std::string> words;
        for (const std::string& word : Split(Trim(line), ' ')) {
            if (!word.empty())
                words.push_back(word);
        }
        if (words.empty())
            continue;
        Route route;
        if (words[0] == "default") {
            route.isDefault = true;
            route.destination = family == AF_INET6 ? "::" : "0.0.0.0";
        } else if (!ParseCidr(words[0], route.destination, route.prefix)) {
            continue;
        }
        for (size_t i = 1; i + 1 < words.size(); i++) {
            if (words[i] == "via")
                route.gateway = words[i + 1];
            else if (words[i] == "dev")
                route.interface = words[i + 1];
        }
        routes.push_back(route);
    }
    pclose(pipe);
    return true;
}


static bool FindDefault(Route& route, int family)
{
    std::vector<Route> routes;
    if (!ListRoutes(routes, family))
        return false;
    for (const Route& candidate : routes) {
        if (candidate.isDefault && !StartsWith(candidate.interface, "tun")) {
            route = candidate;
            return true;
        }
    }
    return false;
}


bool FindDefaultRoute(Route& route)
{
    return FindDefault(route, AF_INET);
}


bool FindDefaultRoute6(Route& route)
{
    return FindDefault(route, AF_INET6);
}


bool AddRoute(const Route& route, std::string& error)
{
    std::vector<std::string> args = {"ip", route.destination.find(':') != std::string::npos ? "-6" : "-4",
        "route", "add", RouteSpec(route)};
    if (!route.gateway.empty()) {
        args.push_back("via");
        args.push_back(route.gateway);
    }
    args.push_back("dev");
    args.push_back(route.interface);
    return Run(args, error);
}


bool DeleteRoute(const Route& route, std::string& error)
{
    std::vector<std::string> args = {"ip", route.destination.find(':') != std::string::npos ? "-6" : "-4",
        "route", "del", RouteSpec(route), "dev", route.interface};
    return Run(args, error);
}


TunDevice::TunDevice()
{
}


TunDevice::~TunDevice()
{
    Close();
}


bool TunDevice::Open(std::string& error)
{
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        error = std::string("/dev/net/tun: ") + strerror(errno);
        return false;
    }
    ifreq request;
    memset(&request, 0, sizeof(request));
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(request.ifr_name, "tun%d", sizeof(request.ifr_name) - 1);
    if (ioctl(fd, TUNSETIFF, &request) < 0) {
        error = std::string("TUNSETIFF: ") + strerror(errno);
        close(fd);
        return false;
    }
    fFd = fd;
    fName = request.ifr_name;
    fCreated = true;
    return true;
}


void TunDevice::Close()
{
    if (fFd >= 0) {
        close(fFd);
        fFd = -1;
    }
    fName.clear();
    fCreated = false;
}


bool TunDevice::SetAddress(const std::string& address, int prefix, const std::string& peer,
    std::string& error)
{
    std::vector<std::string> args = {"ip", "addr", "add", address + "/" + std::to_string(prefix)};
    if (!peer.empty()) {
        args.push_back("peer");
        args.push_back(peer);
    }
    args.push_back("dev");
    args.push_back(fName);
    return Run(args, error);
}


bool TunDevice::SetAddress6(const std::string& address, int prefix, std::string& error)
{
    return Run({"ip", "-6", "addr", "add", address + "/" + std::to_string(prefix), "dev", fName},
        error);
}


bool TunDevice::SetMtu(int mtu, std::string& error)
{
    return Run({"ip", "link", "set", "dev", fName, "mtu", std::to_string(mtu)}, error);
}


bool TunDevice::Up(std::string& error)
{
    return Run({"ip", "link", "set", "dev", fName, "up"}, error);
}

#endif

}  // namespace pvpn
