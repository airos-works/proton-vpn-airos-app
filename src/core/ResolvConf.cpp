#include "ResolvConf.h"
#include "Util.h"
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace pvpn {

const char* const kResolvConfPath = "/boot/system/settings/network/resolv.conf";

namespace {

const char kBegin[] = "# Proton VPN DNS begin";
const char kEnd[] = "# Proton VPN DNS end";
const char kEndWithMarker[] = "# Proton VPN DNS end (dynamic marker added)";
const char kDynamicMarker[] = "# Dynamic DNS entries";

}  // namespace


bool HasVpnDns(const std::string& content)
{
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (StartsWith(line, kBegin))
            return true;
    }
    return false;
}


std::string RemoveVpnDns(const std::string& content)
{
    std::istringstream stream(content);
    std::string line;
    std::string result;
    bool inBlock = false;
    bool dropMarker = false;
    while (std::getline(stream, line)) {
        if (inBlock) {
            if (StartsWith(line, kEnd)) {
                inBlock = false;
                dropMarker = line == kEndWithMarker;
            }
            continue;
        }
        if (StartsWith(line, kBegin)) {
            inBlock = true;
            continue;
        }
        if (dropMarker) {
            dropMarker = false;
            if (line == kDynamicMarker)
                continue;
        }
        result += line + "\n";
    }
    return result;
}


std::string AddVpnDns(const std::string& original, const std::vector<std::string>& servers,
    const std::vector<std::string>& domains, const std::string& owner)
{
    std::string content = RemoveVpnDns(original);
    if (servers.empty() && domains.empty())
        return content;

    bool hasMarker = false;
    {
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            if (StartsWith(line, kDynamicMarker))
                hasMarker = true;
        }
    }

    std::string block = std::string(kBegin) + " (" + owner + ")\n";
    for (const std::string& server : servers)
        block += "nameserver " + server + "\n";
    if (!domains.empty()) {
        block += "search";
        for (const std::string& domain : domains)
            block += " " + domain;
        block += "\n";
    }

    if (hasMarker) {
        // User entries stay first; the VPN goes right above the marker.
        block += std::string(kEnd) + "\n";
        std::istringstream stream(content);
        std::string line;
        std::string result;
        bool inserted = false;
        while (std::getline(stream, line)) {
            if (!inserted && StartsWith(line, kDynamicMarker)) {
                result += block;
                inserted = true;
            }
            result += line + "\n";
        }
        return result;
    }

    // Everything present was written by DHCP (net_server rewrites the whole
    // file then); the VPN goes first and the marker protects it.
    block += std::string(kEndWithMarker) + "\n" + kDynamicMarker + "\n";
    return block + content;
}


static bool WriteFileAtomic(const std::string& path, const std::string& content, int mode = 0644)
{
    struct stat info;
    if (stat(path.c_str(), &info) == 0)
        mode = info.st_mode & 07777;
    std::string temporary = path + ".proton-vpn-new";
    int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return false;
    size_t written = 0;
    while (written < content.size()) {
        ssize_t result = write(fd, content.data() + written, content.size() - written);
        if (result <= 0) {
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


bool ApplyVpnDns(const std::string& path, const std::vector<std::string>& servers,
    const std::vector<std::string>& domains, const std::string& owner)
{
    std::string content;
    ReadFile(path, content);   // a missing file is fine
    return WriteFileAtomic(path, AddVpnDns(content, servers, domains, owner));
}


bool RestoreDns(const std::string& path)
{
    std::string content;
    if (!ReadFile(path, content))
        return true;
    if (!HasVpnDns(content))
        return true;
    return WriteFileAtomic(path, RemoveVpnDns(content));
}

}  // namespace pvpn
