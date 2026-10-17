// The application: owns the core (pvpn::Client), runs its blocking calls on
// worker threads, and drives the windows and the Deskbar tray icon. Flows and
// texts follow the GTK app's controller and widgets (docs/GTK-UI-SPEC.md).
#pragma once
#include "core/Client.h"
#include <Application.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

class KeyStoreSecrets;
class MainWindow;
class SettingsWindow;

class ProtonApp : public BApplication, private pvpn::ClientListener {
public:
    ProtonApp();
    ~ProtonApp() override;

    void ArgvReceived(int32 argc, char** argv) override;
    void ReadyToRun() override;
    bool QuitRequested() override;
    void MessageReceived(BMessage* message) override;

    pvpn::Client& Client() { return *fClient; }
    pvpn::VpnStatus Status() const;
    void SettingsWindowClosed() { fSettings = nullptr; }

    static ProtonApp* Get() { return static_cast<ProtonApp*>(be_app); }

private:
    // pvpn::ClientListener, called on the core's threads.
    void ServerListChanged() override;
    void AccountChanged() override;
    void ConnectionChanged(const pvpn::VpnStatus& status) override;
    void Notice(pvpn::ClientNotice notice, const std::string& detail) override;
    void Log(const std::string& line) override;

    void RunAsync(uint32 what, std::function<void(BMessage&)> work);
    void Startup();
    void SessionReady();
    void ShowLoginScreen();
    void RefreshServers();
    void HandleConnect(BMessage* message);
    void HandleSignOut(BMessage* message);
    void HandleQuitConfirmation(BMessage* message);
    void HandleDisableKillSwitch(BMessage* message);
    void HandleTrayRequest(BMessage* message);
    void ShowSettings();
    void ShowAbout();
    void ShowReleaseNotes();
    void ShowBugReport();
    void ShowAlert(const char* title, const char* text);
    void AutoConnect();
    void InstallTray();
    bool HasTray() const;
    std::string ErrorText(const pvpn::ApiResult& result) const;
    std::string HelperPath(const char* name) const;

    std::unique_ptr<KeyStoreSecrets> fSecrets;
    std::unique_ptr<pvpn::Client> fClient;
    MainWindow* fWindow = nullptr;
    SettingsWindow* fSettings = nullptr;
    mutable std::mutex fStatusLock;
    pvpn::VpnStatus fStatus;
    bool fStartMinimized = false;
    bool fQuitting = false;
    bool fSessionReady = false;
    FILE* fLog = nullptr;
    std::mutex fLogLock;
    std::string fSettingsDirectory;
};
