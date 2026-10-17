// proton-vpn-cli: the app's core without the window, for scripts and tests.
//   proton-vpn-cli [--state DIR] login <user>      (password: $PROTON_VPN_PASSWORD or stdin)
//   proton-vpn-cli [--state DIR] 2fa <code>
//   proton-vpn-cli [--state DIR] logout
//   proton-vpn-cli [--state DIR] info | servers [country] | settings [key=value ...]
//   proton-vpn-cli [--state DIR] connect [fastest|<country>|<server>] [--seconds N]
// connect stays connected for N seconds (default: until Ctrl+C or stdin closes)
// and disconnects before it exits.
#include "core/Client.h"
#include "core/Countries.h"
#include "core/Util.h"
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <unistd.h>

using namespace pvpn;

namespace {

volatile sig_atomic_t sInterrupted = 0;

void OnSignal(int)
{
    sInterrupted = 1;
}

class Printer : public ClientListener {
public:
    bool verbose = false;

    void ConnectionChanged(const VpnStatus& status) override
    {
        std::string line = std::string("state: ") + VpnStateName(status.state) + " ("
            + VpnEventName(status.event) + ")";
        if (status.hasServer)
            line += " " + status.server.logical.name;
        if (!status.message.empty())
            line += ": " + status.message;
        if (status.forwardedPort != 0)
            line += " port " + std::to_string(status.forwardedPort);
        if (!status.deviceIp.empty())
            line += " ip " + status.deviceIp;
        if (line != fLast) {
            printf("%s\n", line.c_str());
            fflush(stdout);
            fLast = line;
        }
    }

    void Notice(ClientNotice notice, const std::string& detail) override
    {
        printf("notice %d: %s\n", (int)notice, detail.c_str());
    }

    void Log(const std::string& line) override
    {
        if (verbose)
            fprintf(stderr, "log: %s\n", line.c_str());
    }

private:
    std::string fLast;
};

std::string DefaultState()
{
#if defined(__HAIKU__)
    return "/boot/home/config/settings/Proton VPN/cli";
#else
    const char* home = getenv("HOME");
    return std::string(home != NULL ? home : ".") + "/.proton-vpn-cli";
#endif
}

std::string BinaryDirectory(const char* argv0)
{
    std::string path = argv0;
    size_t slash = path.rfind('/');
    return slash == std::string::npos ? "." : path.substr(0, slash);
}

int Usage()
{
    fprintf(stderr,
        "usage: proton-vpn-cli [--state DIR] [-v] <command>\n"
        "  login <user>            (password from $PROTON_VPN_PASSWORD or stdin)\n"
        "  2fa <code>\n"
        "  logout\n"
        "  info\n"
        "  servers [country]\n"
        "  settings [protocol=wireguard|openvpn-udp|openvpn-tcp] [netshield=0|1|2]\n"
        "           [killswitch=0|1|2] [portforwarding=0|1] [ipv6=0|1] ...\n"
        "  connect [fastest|<country>|<server>] [--seconds N]\n");
    return 2;
}

const char* ErrorText(const ApiResult& result)
{
    static std::string text;
    text = std::string(ApiErrorName(result.error));
    if (!result.message.empty())
        text += ": " + result.message;
    if (result.code != 0)
        text += " (code " + std::to_string(result.code) + ")";
    return text.c_str();
}

}  // namespace


int main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, OnSignal);
    signal(SIGTERM, OnSignal);
    HttpClient::GlobalInit();

    std::string state = DefaultState();
    bool verbose = false;
    std::vector<std::string> args;
    double seconds = -1;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--state" && i + 1 < argc)
            state = argv[++i];
        else if (arg == "-v")
            verbose = true;
        else if (arg == "--seconds" && i + 1 < argc)
            seconds = atof(argv[++i]);
        else
            args.push_back(arg);
    }
    if (args.empty())
        return Usage();

    std::string binaries = BinaryDirectory(argv[0]);
    ClientPaths paths;
    paths.settingsDirectory = state;
    paths.cacheDirectory = state + "/cache";
    paths.runtimeDirectory = state + "/run";
    paths.openvpnPath = getenv("PROTON_VPN_OPENVPN") ? getenv("PROTON_VPN_OPENVPN")
        : binaries + "/proton-openvpn";
    paths.wireguardPath = getenv("PROTON_VPN_WIREGUARD") ? getenv("PROTON_VPN_WIREGUARD")
        : binaries + "/proton-wireguard";
    if (getenv("PROTON_VPN_RESOLV_CONF"))
        paths.resolvConf = getenv("PROTON_VPN_RESOLV_CONF");
    MakeDirectories(state, 0700);
    FileSecretStore secrets(state + "/session.json");
    Printer printer;
    printer.verbose = verbose;
    Client client(paths, &secrets, &printer);
    client.RestoreSession();

    const std::string& command = args[0];
    if (command == "login") {
        if (args.size() < 2)
            return Usage();
        std::string password = getenv("PROTON_VPN_PASSWORD") ? getenv("PROTON_VPN_PASSWORD") : "";
        if (password.empty())
            std::getline(std::cin, password);
        LoginOutcome outcome = client.Login(args[1], password);
        if (outcome.status == LoginStatus::Failed) {
            fprintf(stderr, "login failed: %s\n", ErrorText(outcome.result));
            return 1;
        }
        if (outcome.status == LoginStatus::TwoFactorRequired) {
            printf("two-factor code required: run proton-vpn-cli 2fa <code>\n");
            return 0;
        }
        ApiResult loaded = client.LoadSessionData();
        if (!loaded.Ok()) {
            fprintf(stderr, "loading the account failed: %s\n", ErrorText(loaded));
            return 1;
        }
        printf("signed in as %s (%s)\n", client.AccountName().c_str(), client.PlanTitle().c_str());
        return 0;
    }
    if (command == "2fa") {
        if (args.size() < 2)
            return Usage();
        LoginOutcome outcome = client.SubmitTwoFactorCode(args[1]);
        if (outcome.status != LoginStatus::Success) {
            fprintf(stderr, "two-factor authentication failed: %s\n", ErrorText(outcome.result));
            return 1;
        }
        ApiResult loaded = client.LoadSessionData();
        if (!loaded.Ok()) {
            fprintf(stderr, "loading the account failed: %s\n", ErrorText(loaded));
            return 1;
        }
        printf("signed in as %s (%s)\n", client.AccountName().c_str(), client.PlanTitle().c_str());
        return 0;
    }
    if (command == "logout") {
        ApiResult result = client.Logout();
        if (!result.Ok()) {
            fprintf(stderr, "sign-out failed: %s\n", ErrorText(result));
            return 1;
        }
        printf("signed out\n");
        return 0;
    }
    if (!client.LoggedIn()) {
        fprintf(stderr, "not signed in\n");
        return 1;
    }
    if (!client.SessionDataLoaded()) {
        ApiResult loaded = client.LoadSessionData();
        if (!loaded.Ok()) {
            fprintf(stderr, "loading the account failed: %s\n", ErrorText(loaded));
            return 1;
        }
    }
    if (command == "info") {
        VpnAccount account = client.Account();
        Settings settings = client.GetSettings();
        CertificateInfo certificate;
        ParseCertificatePem(account.certificate.certificate, certificate);
        printf("account: %s\nplan: %s (tier %d, %d connections)\nlocation: %s %s (%s)\n",
            client.AccountName().c_str(), client.PlanTitle().c_str(), account.info.maxTier,
            account.info.maxConnect, account.location.ip.c_str(), account.location.country.c_str(),
            account.location.isp.c_str());
        printf("certificate: valid until %lld, refresh at %lld\n", (long long)certificate.notAfter,
            (long long)account.certificate.refreshTime);
        printf("settings: %s\n", settings.ToJson().dump().c_str());
        auto servers = client.Servers();
        printf("servers: %zu\n", servers ? servers->Size() : (size_t)0);
        return 0;
    }
    if (command == "servers") {
        auto servers = client.Servers();
        std::string filter = args.size() > 1 ? ToUpper(args[1]) : "";
        for (const CountryGroup& country : servers->GroupByCountry(client.UserTier())) {
            if (!filter.empty() && country.code != filter)
                continue;
            printf("%s %s%s%s\n", country.code.c_str(), country.name.c_str(),
                country.summary.free ? " [free]" : "",
                country.summary.underMaintenance ? " [maintenance]" : "");
            if (filter.empty())
                continue;
            for (const LocationGroup& location : country.locations) {
                printf("  %s\n", location.name.c_str());
                for (const LogicalServer* server : location.servers)
                    printf("    %-12s load %3d%% score %.2f%s\n", server->name.c_str(), server->load,
                        server->score, server->Enabled() ? "" : " (maintenance)");
            }
            for (const LogicalServer* server : country.secureCore)
                printf("  via %s: %s load %d%%\n", CountryName(server->entryCountry).c_str(),
                    server->name.c_str(), server->load);
        }
        return 0;
    }
    if (command == "settings") {
        Settings settings = client.GetSettings();
        for (size_t i = 1; i < args.size(); i++) {
            size_t equals = args[i].find('=');
            if (equals == std::string::npos)
                return Usage();
            std::string key = args[i].substr(0, equals), value = args[i].substr(equals + 1);
            if (key == "protocol")
                settings.protocol = value;
            else if (key == "netshield")
                settings.features.netshield = atoi(value.c_str());
            else if (key == "killswitch")
                settings.killSwitch = atoi(value.c_str());
            else if (key == "portforwarding")
                settings.features.portForwarding = value == "1";
            else if (key == "accelerator")
                settings.features.vpnAccelerator = value == "1";
            else if (key == "moderatenat")
                settings.features.moderateNat = value == "1";
            else if (key == "ipv6")
                settings.ipv6 = value == "1";
            else if (key == "dns") {
                settings.customDnsEnabled = !value.empty();
                settings.customDns = value.empty() ? std::vector<std::string>() : Split(value, ',');
            } else
                return Usage();
        }
        if (args.size() > 1)
            client.SetSettings(settings);
        printf("%s\n", client.GetSettings().ToJson().dump(2).c_str());
        return 0;
    }
    if (command == "connect") {
        std::string target = args.size() > 1 ? args[1] : "fastest";
        std::string error;
        client.StartBackground();
        if (!client.ConnectByCode(target, error)) {
            fprintf(stderr, "cannot connect: %s\n", error.c_str());
            return 1;
        }
        double start = MonotonicNow();
        bool connected = false;
        while (!sInterrupted) {
            VpnStatus status = client.Status();
            if (status.state == VpnState::Connected && !connected) {
                connected = true;
                printf("connected to %s via %s in %.1f s\n", status.server.logical.name.c_str(),
                    status.server.protocol.c_str(), MonotonicNow() - start);
                fflush(stdout);
                if (seconds < 0 && !isatty(STDIN_FILENO)) {
                    // Scripts: stay until stdin closes.
                }
            }
            if (seconds >= 0 && MonotonicNow() - start >= seconds)
                break;
            pollfd input = {STDIN_FILENO, POLLIN, 0};
            if (seconds < 0 && poll(&input, 1, 200) > 0) {
                char buffer[64];
                if (read(STDIN_FILENO, buffer, sizeof(buffer)) <= 0)
                    break;
            } else {
                usleep(200000);
            }
        }
        VpnStatus final = client.Status();
        client.Disconnect();
        client.WaitForDisconnected(20);
        client.StopBackground();
        printf("disconnected (was %s)\n", VpnStateName(final.state));
        return connected ? 0 : 1;
    }
    return Usage();
}
