#include "App.h"
#include "BugReportWindow.h"
#include "KeyStoreSecrets.h"
#include "MainWindow.h"
#include "Messages.h"
#include "SettingsWindow.h"
#include "VpnView.h"
#include "Widgets.h"
#include "core/Countries.h"
#include "core/Util.h"
#include <AboutWindow.h>
#include <Alert.h>
#include <Deskbar.h>
#include <Entry.h>
#include <FindDirectory.h>
#include <Invoker.h>
#include <MessageRunner.h>
#include <Notification.h>
#include <Path.h>
#include <Roster.h>
#include <Screen.h>
#include <ScrollView.h>
#include <TextView.h>
#include <ctime>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace pvpn;

const char* const kAppSignature = "application/x-vnd.ProtonVPN";

namespace {

const char kVersion[] = "0.1.0";
const char kTrayName[] = "Proton VPN";

const uint32 kMsgSignOutConfirmed = 'soco';
const uint32 kMsgQuitConfirmed = 'quco';
const uint32 kMsgQuitReady = 'qurd';
const uint32 kMsgKillSwitchConfirmed = 'kico';
const uint32 kMsgRetryLoad = 'rtld';

const char kReleaseNotes[] =
    "What's new (0.1.0)\n\n"
    "- First release of Proton VPN for air/OS: a native port of the Proton VPN Linux app "
    "(GTK app 4.18.7, API core 5.8.7).\n"
    "- Sign in with two-factor codes, server list with countries, cities and Secure Core, "
    "search, quick connect and auto connect.\n"
    "- WireGuard (userspace, built in) and OpenVPN (UDP and TCP).\n"
    "- NetShield, VPN Accelerator, moderate NAT and port forwarding through the server's "
    "local agent.\n"
    "- Kill switch (standard and advanced), custom DNS, IPv6.\n"
    "- Deskbar tray icon with pinned connections.\n";

std::string FindPath(directory_which which, const char* leaf)
{
    BPath path;
    if (find_directory(which, &path, true) != B_OK)
        return std::string("/boot/home/config/settings/") + leaf;
    path.Append(leaf);
    return path.Path();
}

}  // namespace


ProtonApp::ProtonApp()
    :
    BApplication(kAppSignature)
{
}


ProtonApp::~ProtonApp()
{
    if (fLog != nullptr)
        fclose(fLog);
}


VpnStatus ProtonApp::Status() const
{
    std::lock_guard<std::mutex> lock(fStatusLock);
    return fStatus;
}


void ProtonApp::ArgvReceived(int32 argc, char** argv)
{
    for (int32 i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--start-minimized") {
            fStartMinimized = true;
        } else if (arg == "-v" || arg == "--version") {
            printf("Proton VPN %s\n", kVersion);
            fQuitting = true;
            PostMessage(B_QUIT_REQUESTED);
        } else if (arg == "--connect" && i + 1 < argc) {
            BMessage connect(kMsgConnectCode);
            connect.AddString("code", argv[++i]);
            PostMessage(&connect);
        } else if (arg == "--disconnect") {
            PostMessage(kMsgDisconnect);
        }
    }
}


std::string ProtonApp::HelperPath(const char* name) const
{
    app_info info;
    if (GetAppInfo(&info) != B_OK)
        return name;
    BPath directory(&info.ref);
    directory.GetParent(&directory);
    // The package keeps the helpers in "helpers"; a build tree has them next
    // to the app, OpenVPN in "openvpn".
    for (const char* sub : {"helpers/", "", "openvpn/"}) {
        std::string path = std::string(directory.Path()) + "/" + sub + name;
        if (access(path.c_str(), X_OK) == 0)
            return path;
    }
    return std::string(directory.Path()) + "/helpers/" + name;
}


void ProtonApp::ReadyToRun()
{
    if (fQuitting)
        return;
    fSettingsDirectory = FindPath(B_USER_SETTINGS_DIRECTORY, "Proton VPN");
    MakeDirectories(fSettingsDirectory, 0700);
    std::string logPath = fSettingsDirectory + "/proton-vpn.log";
    struct stat info;
    if (stat(logPath.c_str(), &info) == 0 && info.st_size > 2 * 1024 * 1024)
        rename(logPath.c_str(), (logPath + ".old").c_str());
    fLog = fopen(logPath.c_str(), "a");
    Log(std::string("Proton VPN ") + kVersion + " starting");

    HttpClient::GlobalInit();
    ClientPaths paths;
    paths.settingsDirectory = fSettingsDirectory;
    paths.cacheDirectory = FindPath(B_USER_CACHE_DIRECTORY, "Proton VPN");
    paths.runtimeDirectory = FindPath(B_SYSTEM_TEMP_DIRECTORY, "proton-vpn");
    paths.openvpnPath = HelperPath("proton-openvpn");
    paths.wireguardPath = HelperPath("proton-wireguard");
    fSecrets.reset(new KeyStoreSecrets(fSettingsDirectory + "/session.json"));
    fClient.reset(new pvpn::Client(paths, fSecrets.get(), this));

    float scale = be_plain_font->Size() / 12.0f;
    BRect frame(0, 0, 460 * scale, 720 * scale);
    std::string saved;
    if (ReadFile(fSettingsDirectory + "/window", saved)) {
        float left, top, right, bottom;
        if (sscanf(saved.c_str(), "%f %f %f %f", &left, &top, &right, &bottom) == 4)
            frame.Set(left, top, right, bottom);
    } else {
        BRect screen = BScreen().Frame();
        // Leave room for the title tab and the Deskbar on small screens.
        if (frame.Height() > screen.Height() - 80 * scale)
            frame.bottom = frame.top + screen.Height() - 80 * scale;
        frame.OffsetTo((screen.Width() - frame.Width()) / 2,
            std::max(30 * scale, (screen.Height() - frame.Height()) / 3));
    }
    if (!BScreen().Frame().Intersects(frame))
        frame.OffsetTo(80, 80);
    fWindow = new MainWindow(frame);
    InstallTray();
    bool minimized = (fStartMinimized || fClient->GetAppConfig().startMinimized) && HasTray();
    if (minimized)
        fWindow->Hide();
    fWindow->Show();
    Startup();
}


void ProtonApp::RunAsync(uint32 what, std::function<void(BMessage&)> work)
{
    BMessenger target(this);
    std::thread([target, what, work]() {
        BMessage reply(what);
        work(reply);
        target.SendMessage(&reply);
    }).detach();
}


std::string ProtonApp::ErrorText(const ApiResult& result) const
{
    switch (result.error) {
        case ApiError::None:
            return "";
        case ApiError::NotReachable:
            return "Our servers are not reachable. Please check your internet connection.";
        case ApiError::BadCredentials:
            return "Incorrect credentials.";
        default:
            break;
    }
    if (!result.message.empty())
        return result.message;
    return "We're sorry, an unexpected error occurred. Please try again.";
}


void ProtonApp::Startup()
{
    if (fWindow->LockLooper()) {
        fWindow->ShowLoading("Loading app...");
        fWindow->UnlockLooper();
    }
    // Reading the key store may wait for the user to allow it.
    RunAsync(kMsgSessionLoaded, [this](BMessage& reply) {
        bool restored = fClient->LoggedIn() || fClient->RestoreSession();
        reply.AddBool("restored", restored);
        if (!restored)
            return;
        ApiResult result;
        if (!fClient->SessionDataLoaded())
            result = fClient->LoadSessionData();
        reply.AddBool("ok", result.Ok());
        reply.AddInt32("error", (int32)result.error);
        reply.AddString("text", ErrorText(result).c_str());
    });
}


void ProtonApp::ShowLoginScreen()
{
    fSessionReady = false;
    if (fSettings != nullptr && fSettings->Lock())
        fSettings->Quit();
    fSettings = nullptr;
    bool blocking = fClient->GetSettings().killSwitch == kKillSwitchAdvanced;
    if (fWindow->LockLooper()) {
        fWindow->ShowLogin(blocking);
        fWindow->UnlockLooper();
    }
}


void ProtonApp::SessionReady()
{
    fSessionReady = true;
    fClient->StartBackground();
    if (fWindow->LockLooper()) {
        fWindow->ShowVpn();
        fWindow->SetStatus(Status());
        fWindow->UnlockLooper();
    }
    RefreshServers();
    if (!fPendingConnect.empty()) {
        BMessage connect(kMsgConnectCode);
        connect.AddString("code", fPendingConnect.c_str());
        fPendingConnect.clear();
        HandleConnect(&connect);
    } else {
        AutoConnect();
    }
}


void ProtonApp::RefreshServers()
{
    if (!fSessionReady)
        return;
    if (fWindow->LockLooper()) {
        fWindow->SetServers(fClient->Servers(), fClient->UserTier(),
            fClient->ServerSelectionRequiresUpgrade(), fClient->Config());
        fWindow->UnlockLooper();
    }
}


void ProtonApp::AutoConnect()
{
    std::string code = fClient->GetAppConfig().connectAtStartup;
    if (code.empty() || fClient->ServerSelectionRequiresUpgrade())
        return;
    if (Status().state != VpnState::Disconnected)
        return;
    std::string error;
    Log("Auto connect: " + code);
    if (!fClient->ConnectByCode(code, error))
        ShowAlert("Unable to find server", error.c_str());
}


void ProtonApp::ShowAlert(const char* title, const char* text)
{
    BAlert* alert = new BAlert(title, text, "OK", nullptr, nullptr, B_WIDTH_AS_USUAL, B_WARNING_ALERT);
    alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
    BString windowTitle(title);
    alert->SetTitle(windowTitle.String());
    alert->Go(nullptr);
}


void ProtonApp::InstallTray()
{
    BDeskbar deskbar;
    if (deskbar.HasItem(kTrayName))
        return;
    app_info info;
    if (GetAppInfo(&info) == B_OK)
        deskbar.AddItem(&info.ref);
}


bool ProtonApp::HasTray() const
{
    return BDeskbar().HasItem(kTrayName);
}


bool ProtonApp::QuitRequested()
{
    if (fQuitting) {
        if (fWindow != nullptr && fWindow->LockLooper()) {
            BRect frame = fWindow->Frame();
            char text[128];
            snprintf(text, sizeof(text), "%.0f %.0f %.0f %.0f", frame.left, frame.top, frame.right,
                frame.bottom);
            WriteFile(fSettingsDirectory + "/window", text, 0644);
            fWindow->UnlockLooper();
        }
        if (fClient) {
            fClient->StopBackground();
            fClient.reset();
        }
        BDeskbar().RemoveItem(kTrayName);
        Log("Quit");
        return true;
    }
    VpnStatus status = Status();
    if (!fClient || (status.state == VpnState::Disconnected && !status.reconnecting)) {
        fQuitting = true;
        return QuitRequested();
    }
    bool permanent = fClient->GetSettings().killSwitch == kKillSwitchAdvanced;
    const char* text = permanent
        ? "Quitting the application will keep the kill switch active, but your current VPN "
          "connection will be terminated.\n\nDo you want to continue?"
        : "Quitting the application will cancel the current VPN connection.\n\n"
          "Do you want to continue?";
    BAlert* alert = new BAlert("Active connection found", text, "No", "Yes", nullptr,
        B_WIDTH_AS_USUAL, B_WARNING_ALERT);
    alert->SetShortcut(0, B_ESCAPE);
    alert->Go(new BInvoker(new BMessage(kMsgQuitConfirmed), this));
    if (fWindow->LockLooper()) {
        if (fWindow->IsHidden())
            fWindow->Show();
        fWindow->UnlockLooper();
    }
    return false;
}


void ProtonApp::HandleQuitConfirmation(BMessage* message)
{
    if (message->GetInt32("which", 0) != 1)
        return;
    if (fWindow->LockLooper()) {
        fWindow->ShowLoading("Disconnecting...");
        fWindow->UnlockLooper();
    }
    RunAsync(kMsgQuitReady, [this](BMessage&) {
        fClient->Disconnect();
        fClient->WaitForDisconnected(20);
    });
}


void ProtonApp::HandleSignOut(BMessage* message)
{
    if (message->what == kMsgSignOut) {
        VpnStatus status = Status();
        Settings settings = fClient->GetSettings();
        const char* title = nullptr;
        const char* text = nullptr;
        if (status.state != VpnState::Disconnected || status.reconnecting) {
            title = "Active connection found";
            text = settings.killSwitch == kKillSwitchOff
                ? "Signing out will cancel the current VPN connection.\n\nDo you want to continue?"
                : "Signing out will cancel the current VPN connection and disable the kill "
                  "switch.\n\nDo you want to continue?";
        } else if (settings.killSwitch == kKillSwitchAdvanced) {
            title = "Kill Switch enabled";
            text = "Signing out will disable the kill switch, potentially exposing your internet "
                "traffic. \n\nDo you want to continue?";
        }
        if (title != nullptr) {
            BAlert* alert = new BAlert(title, text, "No", "Yes", nullptr, B_WIDTH_AS_USUAL,
                B_WARNING_ALERT);
            alert->SetShortcut(0, B_ESCAPE);
            alert->Go(new BInvoker(new BMessage(kMsgSignOutConfirmed), this));
            return;
        }
    } else if (message->GetInt32("which", 0) != 1) {
        return;
    }
    if (fWindow->LockLooper()) {
        fWindow->ShowLoading("Signing out...");
        fWindow->UnlockLooper();
    }
    Settings settings = fClient->GetSettings();
    if (settings.killSwitch != kKillSwitchOff) {
        settings.killSwitch = kKillSwitchOff;
        fClient->SetSettings(settings);
    }
    RunAsync(kMsgLogoutResult, [this](BMessage& reply) {
        ApiResult result = fClient->Logout();
        reply.AddBool("ok", result.Ok());
    });
}


void ProtonApp::HandleDisableKillSwitch(BMessage* message)
{
    if (message->what == kMsgDisableKillSwitch) {
        BAlert* alert = new BAlert("Kill Switch Enabled",
            "Permanent Kill Switch is blocking any outgoing connections and preventing your IP to be "
            "exposed.\n\nDo you want to disable Kill Switch?", "No", "Yes", nullptr,
            B_WIDTH_AS_USUAL, B_WARNING_ALERT);
        alert->SetShortcut(0, B_ESCAPE);
        alert->Go(new BInvoker(new BMessage(kMsgKillSwitchConfirmed), this));
        return;
    }
    if (message->GetInt32("which", 0) != 1)
        return;
    Settings settings = fClient->GetSettings();
    settings.killSwitch = kKillSwitchOff;
    fClient->SetSettings(settings);
    if (fWindow->LockLooper()) {
        fWindow->SetKillSwitchBlocking(false);
        fWindow->UnlockLooper();
    }
}


void ProtonApp::HandleConnect(BMessage* message)
{
    std::string error;
    bool ok = true;
    std::string code = message->GetString("code", "");
    switch (message->what) {
        case kMsgQuickConnect:
            ok = fClient->ConnectFastest(error);
            break;
        case kMsgConnectCountry:
            ok = fClient->ConnectCountry(code, error);
            break;
        case kMsgConnectLocation:
            ok = fClient->ConnectLocation(code, message->GetString("location", ""), error);
            break;
        case kMsgConnectSecureCore:
            ok = fClient->ConnectSecureCore(code, error);
            break;
        case kMsgConnectServer: {
            BString id = message->GetString("id", "");
            ok = id.Length() > 0 ? fClient->ConnectServerId(id.String(), error)
                : fClient->ConnectServer(message->GetString("name", ""), error);
            break;
        }
        case kMsgConnectCode:
            ok = fClient->ConnectByCode(code, error);
            break;
        case kMsgChangeServer: {
            // A random server (no Secure Core, no Tor, not the current one), in
            // the country of the last country-level connection if there was one.
            std::shared_ptr<const ServerList> servers = fClient->Servers();
            if (!servers) {
                ok = false;
                error = "No server available in the current tier";
                break;
            }
            std::string country = fClient->LastRequestedCountry();
            std::string current = Status().hasServer ? Status().server.logical.id : "";
            std::vector<const LogicalServer*> candidates;
            for (const LogicalServer& server : servers->Servers()) {
                if (server.features & (kFeatureSecureCore | kFeatureTor))
                    continue;
                if (!server.Enabled() || server.tier > fClient->UserTier())
                    continue;
                if (!country.empty() && ToUpper(server.exitCountry) != country)
                    continue;
                candidates.push_back(&server);
            }
            if (candidates.size() > 1) {
                candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                    [&](const LogicalServer* server) { return server->id == current; }),
                    candidates.end());
            }
            if (candidates.empty()) {
                ok = false;
                error = "No server available in the current tier";
                break;
            }
            const LogicalServer* pick = candidates[(size_t)(RandomUnit() * candidates.size())
                % candidates.size()];
            ok = fClient->ConnectServerId(pick->id, error);
            break;
        }
    }
    if (!ok)
        ShowAlert("Unable to find server", error.c_str());
}


void ProtonApp::HandleTrayRequest(BMessage* message)
{
    BMessage reply(kMsgTrayState);
    VpnStatus status = Status();
    reply.AddInt32("state", (int32)status.state);
    reply.AddBool("reconnecting", status.reconnecting);
    reply.AddBool("logged_in", fSessionReady);
    bool visible = false;
    if (fWindow->LockLooper()) {
        visible = !fWindow->IsHidden() && !fWindow->IsMinimized();
        fWindow->UnlockLooper();
    }
    reply.AddBool("visible", visible);
    if (fSessionReady && !fClient->ServerSelectionRequiresUpgrade()) {
        for (const std::string& pin : fClient->GetAppConfig().trayPinnedServers)
            reply.AddString("pin", pin.c_str());
    }
    message->SendReply(&reply);
}


void ProtonApp::ShowSettings()
{
    if (!fSessionReady)
        return;
    if (fSettings == nullptr) {
        fSettings = new SettingsWindow(fWindow);
        fSettings->Show();
    } else if (fSettings->Lock()) {
        fSettings->Activate();
        fSettings->Unlock();
    }
}


void ProtonApp::ShowAbout()
{
    BAboutWindow* about = new BAboutWindow("Proton VPN", kAppSignature);
    about->AddDescription("Proton VPN for air/OS: a native port of the Proton VPN Linux app "
        "with a Haiku user interface. Fast, private and secure VPN.");
    about->AddCopyright(2026, "Proton AG");
    about->AddText("Haiku port", nullptr);
    about->AddText("Licensed under the GNU General Public License version 3 or later.");
    about->AddText("https://protonvpn.com");
    about->AddText("Proton VPN is a trademark of Proton AG. This port uses the Proton VPN API "
        "like the official Linux app.");
    about->Show();
}


void ProtonApp::ShowReleaseNotes()
{
    BWindow* window = new BWindow(BRect(0, 0, 450, 400), "Release notes", B_TITLED_WINDOW,
        B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE);
    BTextView* text = new BTextView("notes");
    text->MakeEditable(false);
    text->SetWordWrap(true);
    text->SetText(kReleaseNotes);
    text->SetInsets(10, 10, 10, 10);
    BScrollView* scroll = new BScrollView("scroll", text, 0, false, true);
    window->SetLayout(new BGroupLayout(B_VERTICAL));
    window->AddChild(scroll);
    float scale = be_plain_font->Size() / 12.0f;
    window->ResizeTo(450 * scale, 360 * scale);
    window->CenterIn(fWindow->Frame());
    window->Show();
}


void ProtonApp::ShowBugReport()
{
    BugReportWindow* window = new BugReportWindow(fWindow->Frame(), fClient->AccountName().c_str(),
        fSettingsDirectory + "/proton-vpn.log");
    window->Show();
}


void ProtonApp::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgLogin: {
            std::string username = message->GetString("username", "");
            std::string password = message->GetString("password", "");
            RunAsync(kMsgLoginResult, [this, username, password](BMessage& reply) {
                LoginOutcome outcome = fClient->Login(username, password);
                reply.AddInt32("status", (int32)outcome.status);
                reply.AddInt32("error", (int32)outcome.result.error);
                reply.AddString("text", ErrorText(outcome.result).c_str());
                if (outcome.status == LoginStatus::Success) {
                    ApiResult loaded = fClient->LoadSessionData();
                    reply.AddBool("loaded", loaded.Ok());
                    reply.AddString("load_text", ErrorText(loaded).c_str());
                }
            });
            break;
        }
        case kMsgLoginResult: {
            LoginStatus status = (LoginStatus)message->GetInt32("status", 0);
            if (fWindow->LockLooper()) {
                fWindow->LoginFinished(status != LoginStatus::Failed);
                if (status == LoginStatus::TwoFactorRequired) {
                    fWindow->ShowTwoFactor();
                } else if (status == LoginStatus::Failed) {
                    fWindow->Notify(message->GetString("text", ""));
                } else if (!message->GetBool("loaded", false)) {
                    fWindow->ShowLoading("Loading app...");
                    fWindow->Notify(message->GetString("load_text", ""));
                    BMessage retry(kMsgRetryLoad);
                    BMessageRunner::StartSending(this, &retry, 10000000, 1);
                }
                fWindow->UnlockLooper();
            }
            if (status == LoginStatus::Success && message->GetBool("loaded", false))
                SessionReady();
            break;
        }
        case kMsgSubmitTwoFactor: {
            std::string code = message->GetString("code", "");
            RunAsync(kMsgTwoFactorResult, [this, code](BMessage& reply) {
                LoginOutcome outcome = fClient->SubmitTwoFactorCode(code);
                reply.AddInt32("status", (int32)outcome.status);
                reply.AddInt32("error", (int32)outcome.result.error);
                reply.AddString("text", ErrorText(outcome.result).c_str());
                if (outcome.status == LoginStatus::Success) {
                    ApiResult loaded = fClient->LoadSessionData();
                    reply.AddBool("loaded", loaded.Ok());
                    reply.AddString("load_text", ErrorText(loaded).c_str());
                }
            });
            break;
        }
        case kMsgTwoFactorResult: {
            LoginStatus status = (LoginStatus)message->GetInt32("status", 0);
            ApiError error = (ApiError)message->GetInt32("error", 0);
            if (fWindow->LockLooper()) {
                fWindow->TwoFactorFinished(status == LoginStatus::Success);
                if (status != LoginStatus::Success) {
                    if (error == ApiError::AuthenticationNeeded) {
                        fWindow->ShowLogin(false);
                        fWindow->Notify(message->GetString("text", "Incorrect 2FA code."));
                    } else if (error == ApiError::NotReachable) {
                        fWindow->Notify(message->GetString("text", ""));
                    } else {
                        fWindow->Notify("Incorrect 2FA code.");
                    }
                } else if (!message->GetBool("loaded", false)) {
                    fWindow->ShowLoading("Loading app...");
                    fWindow->Notify(message->GetString("load_text", ""));
                    BMessage retry(kMsgRetryLoad);
                    BMessageRunner::StartSending(this, &retry, 10000000, 1);
                }
                fWindow->UnlockLooper();
            }
            if (status == LoginStatus::Success && message->GetBool("loaded", false))
                SessionReady();
            break;
        }
        case kMsgCancelTwoFactor:
            if (fWindow->LockLooper()) {
                fWindow->ShowLoading("Signing out...");
                fWindow->UnlockLooper();
            }
            RunAsync(kMsgLogoutResult, [this](BMessage& reply) {
                reply.AddBool("ok", fClient->Logout().Ok());
            });
            break;
        case kMsgSessionLoaded:
            if (!message->GetBool("restored", true)) {
                ShowLoginScreen();
            } else if (message->GetBool("ok", false)) {
                SessionReady();
            } else if ((ApiError)message->GetInt32("error", 0) == ApiError::AuthenticationNeeded) {
                ShowLoginScreen();
            } else {
                if (fWindow->LockLooper()) {
                    fWindow->Notify(message->GetString("text", ""));
                    fWindow->UnlockLooper();
                }
                BMessage retry(kMsgRetryLoad);
                BMessageRunner::StartSending(this, &retry, 10000000, 1);
            }
            break;
        case kMsgRetryLoad:
            if (!fSessionReady && fClient->LoggedIn())
                Startup();
            break;
        case kMsgLogoutResult:
            if (message->GetBool("ok", false)) {
                ShowLoginScreen();
            } else if (fWindow->LockLooper()) {
                fWindow->ShowVpn();
                fWindow->Notify("Unable to sign out, please ensure you have internet access.");
                fWindow->UnlockLooper();
            }
            break;

        case kMsgQuickConnect:
        case kMsgConnectCountry:
        case kMsgConnectLocation:
        case kMsgConnectSecureCore:
        case kMsgConnectServer:
        case kMsgConnectCode:
        case kMsgChangeServer:
            if (fSessionReady)
                HandleConnect(message);
            else if (message->what == kMsgConnectCode)
                fPendingConnect = message->GetString("code", "");
            break;
        case kMsgDisconnect:
            if (fClient)
                fClient->Disconnect();
            break;

        case kMsgSignOut:
        case kMsgSignOutConfirmed:
            HandleSignOut(message);
            break;
        case kMsgQuitConfirmed:
            HandleQuitConfirmation(message);
            break;
        case kMsgQuitReady:
            fQuitting = true;
            PostMessage(B_QUIT_REQUESTED);
            break;
        case kMsgDisableKillSwitch:
        case kMsgKillSwitchConfirmed:
            HandleDisableKillSwitch(message);
            break;

        case kMsgVpnStatus: {
            VpnStatus status = Status();
            if (fWindow->LockLooper()) {
                fWindow->SetStatus(status);
                fWindow->UnlockLooper();
            }
            if (fSettings != nullptr) {
                BMessage update(kMsgVpnStatus);
                fSettings->PostMessage(&update);
            }
            break;
        }
        case kMsgServerListChanged:
            RefreshServers();
            break;
        case kMsgAccountChanged:
            RefreshServers();
            if (fSettings != nullptr)
                fSettings->PostMessage(kMsgAccountChanged);
            break;
        case kMsgNotice: {
            ClientNotice notice = (ClientNotice)message->GetInt32("notice", 0);
            BString detail = message->GetString("detail", "");
            switch (notice) {
                case ClientNotice::SessionExpired:
                    // Signed out by the API: no connection without a session.
                    fClient->Disconnect();
                    fClient->StopBackground();
                    ShowAlert("Invalid Session", "Your session has expired. Please sign in again.");
                    ShowLoginScreen();
                    break;
                case ClientNotice::VpnConnectionError:
                    ShowAlert("VPN connection error",
                        "Proton VPN could not connect to the VPN and blocked access to Internet to "
                        "protect your IP.\n\nClick \"Cancel Connection\" to restore your Internet "
                        "connection. If the issue persists please try to sign out and in.");
                    break;
                case ClientNotice::TwoFactorRequired:
                    ShowAlert("2FA Required",
                        "You are connected to the VPN, but all traffic is blocked.\nYou need to go "
                        "to the authentication page provided by security and authenticate with "
                        "your hardware key.\nAfter that, the traffic will be enabled.");
                    break;
                case ClientNotice::UpdateSystemClock:
                    ShowAlert("Update system clock",
                        "Looks like your system clock is out of sync.\nThis may cause issues when "
                        "connecting to VPN.\nUpdate your system time and try to connect again.");
                    break;
                case ClientNotice::SessionLimitReached:
                    ShowAlert("Connection error: session limit reached",
                        "You've reached your maximum device limit. To reconnect to VPN, please "
                        "disconnect from another device.");
                    break;
                case ClientNotice::PortForwardChanged: {
                    bool active = false;
                    if (fWindow->LockLooper()) {
                        active = fWindow->IsActive();
                        fWindow->UnlockLooper();
                    }
                    if (!active) {
                        BNotification notification(B_INFORMATION_NOTIFICATION);
                        notification.SetGroup("Proton VPN");
                        notification.SetTitle("Port forwarding");
                        BString content;
                        content << "Active port is " << detail;
                        notification.SetContent(content);
                        notification.Send();
                    }
                    break;
                }
            }
            break;
        }

        case kMsgRefreshServers:
            if (!fSessionReady)
                break;
            RunAsync(kMsgServersRefreshed, [this](BMessage& reply) {
                ApiResult result = fClient->RefreshServerList();
                reply.AddBool("ok", result.Ok());
                reply.AddBool("expired", result.error == ApiError::AuthenticationNeeded);
                reply.AddString("text", ErrorText(result).c_str());
            });
            break;
        case kMsgServersRefreshed:
            // An expired session has its own dialog.
            if (message->GetBool("expired", false))
                break;
            if (fWindow->LockLooper()) {
                if (message->GetBool("ok", false))
                    fWindow->Notify("Server list updated", kNotificationSuccess, 3000000);
                else
                    fWindow->Notify(message->GetString("text", ""));
                fWindow->UnlockLooper();
            }
            break;
        case kMsgShowSettings:
            ShowSettings();
            break;
        case kMsgShowAbout:
            ShowAbout();
            break;
        case kMsgShowReleaseNotes:
            ShowReleaseNotes();
            break;
        case kMsgShowBugReport:
            ShowBugReport();
            break;
        case kMsgOpenUrl:
            OpenUrl(message->GetString("url", ""));
            break;
        case kMsgShowWindow:
        case kMsgToggleWindow:
            if (fWindow->LockLooper()) {
                if (message->what == kMsgToggleWindow && !fWindow->IsHidden()
                    && !fWindow->IsMinimized()) {
                    fWindow->Hide();
                } else {
                    if (fWindow->IsHidden())
                        fWindow->Show();
                    fWindow->Minimize(false);
                    fWindow->Activate();
                }
                fWindow->UnlockLooper();
            }
            break;
        case kMsgGetTrayState:
            HandleTrayRequest(message);
            break;
        case kMsgSettingsChanged:
            RefreshServers();
            break;
        default:
            BApplication::MessageReceived(message);
    }
}


// --- pvpn::ClientListener (core threads) ----------------------------------------

void ProtonApp::ServerListChanged()
{
    PostMessage(kMsgServerListChanged);
}


void ProtonApp::AccountChanged()
{
    PostMessage(kMsgAccountChanged);
}


void ProtonApp::ConnectionChanged(const VpnStatus& status)
{
    {
        std::lock_guard<std::mutex> lock(fStatusLock);
        bool changed = status.state != fStatus.state || status.event != fStatus.event
            || status.forwardedPort != fStatus.forwardedPort || status.deviceIp != fStatus.deviceIp
            || status.reconnecting != fStatus.reconnecting
            || status.connectionId != fStatus.connectionId;
        fStatus = status;
        if (!changed)
            return;   // traffic counters only
    }
    PostMessage(kMsgVpnStatus);
}


void ProtonApp::Notice(ClientNotice notice, const std::string& detail)
{
    BMessage message(kMsgNotice);
    message.AddInt32("notice", (int32)notice);
    message.AddString("detail", detail.c_str());
    PostMessage(&message);
}


void ProtonApp::Log(const std::string& line)
{
    std::lock_guard<std::mutex> lock(fLogLock);
    if (fLog == nullptr)
        return;
    time_t now = time(nullptr);
    struct tm parts;
    localtime_r(&now, &parts);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &parts);
    fprintf(fLog, "%s %s\n", stamp, line.c_str());
    fflush(fLog);
}
