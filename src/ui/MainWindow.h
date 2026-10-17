// The main window: a menu bar (the GTK app's header menu, plus a Connection
// menu), the notification bar, and one of the login, two-factor, loading or
// VPN screens.
#pragma once
#include "Widgets.h"
#include "core/Account.h"
#include "core/Connector.h"
#include "core/ServerList.h"
#include <Window.h>
#include <memory>

class BCardLayout;
class BMenuItem;
class LoadingView;
class LoginView;
class TwoFactorView;
class VpnView;

class MainWindow : public BWindow {
public:
    MainWindow(BRect frame);

    bool QuitRequested() override;
    void MessageReceived(BMessage* message) override;
    void MenusBeginning() override;

    void ShowLogin(bool killSwitchBlocking);
    void ShowTwoFactor();
    void ShowLoading(const char* text);
    void ShowVpn();
    bool ShowingVpn() const;
    void Notify(const char* text, NotificationKind kind = kNotificationError,
        bigtime_t duration = 10000000);
    void LoginFinished(bool success);
    void TwoFactorFinished(bool success);
    void SetKillSwitchBlocking(bool blocking);

    void SetStatus(const pvpn::VpnStatus& status);
    void SetServers(std::shared_ptr<const pvpn::ServerList> servers, int userTier, bool rescope,
        const pvpn::ClientConfig& config);
    VpnView* Vpn() const { return fVpn; }

private:
    BCardLayout* fCards;
    NotificationBar* fNotification;
    LoginView* fLogin;
    TwoFactorView* fTwoFactor;
    LoadingView* fLoading;
    VpnView* fVpn;
    BMenuItem* fSettingsItem;
    BMenuItem* fSignOutItem;
    BMenuItem* fConnectItem;
    BMenuItem* fDisconnectItem;
    BMenuItem* fFindItem;
    pvpn::VpnStatus fStatus;
};
