#include "MainWindow.h"
#include "LoginViews.h"
#include "Messages.h"
#include "ServerListView.h"
#include "VpnView.h"
#include <Application.h>
#include <CardLayout.h>
#include <Deskbar.h>
#include <GroupLayout.h>
#include <LayoutBuilder.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Screen.h>

namespace {

enum Card {
    kCardLogin,
    kCardTwoFactor,
    kCardLoading,
    kCardVpn,
};

}  // namespace


MainWindow::MainWindow(BRect frame)
    :
    BWindow(frame, "Proton VPN", B_TITLED_WINDOW,
        B_ASYNCHRONOUS_CONTROLS | B_AUTO_UPDATE_SIZE_LIMITS | B_QUIT_ON_WINDOW_CLOSE * 0)
{
    BMenuBar* menuBar = new BMenuBar("menu");
    BMenu* app = new BMenu("Proton VPN");
    app->AddItem(new BMenuItem("About Proton VPN" B_UTF8_ELLIPSIS, new BMessage(kMsgShowAbout)));
    app->AddSeparatorItem();
    fSettingsItem = new BMenuItem("Settings" B_UTF8_ELLIPSIS, new BMessage(kMsgShowSettings), ',');
    app->AddItem(fSettingsItem);
    app->AddSeparatorItem();
    app->AddItem(new BMenuItem("Release notes", new BMessage(kMsgShowReleaseNotes)));
    app->AddItem(new BMenuItem("Report an issue" B_UTF8_ELLIPSIS, new BMessage(kMsgShowBugReport)));
    app->AddSeparatorItem();
    fSignOutItem = new BMenuItem("Sign out", new BMessage(kMsgSignOut));
    app->AddItem(fSignOutItem);
    app->AddSeparatorItem();
    app->AddItem(new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q'));
    app->SetTargetForItems(be_app);
    menuBar->AddItem(app);

    BMenu* connection = new BMenu("Connection");
    fConnectItem = new BMenuItem("Quick connect", new BMessage(kMsgQuickConnect), 'K');
    fDisconnectItem = new BMenuItem("Disconnect", new BMessage(kMsgDisconnect), 'D');
    fFindItem = new BMenuItem("Find" B_UTF8_ELLIPSIS, new BMessage(kMsgFocusSearch), 'F');
    connection->AddItem(fConnectItem);
    connection->AddItem(fDisconnectItem);
    connection->AddSeparatorItem();
    connection->AddItem(fFindItem);
    menuBar->AddItem(connection);

    fNotification = new NotificationBar();
    fLogin = new LoginView();
    fTwoFactor = new TwoFactorView();
    fLoading = new LoadingView();
    fVpn = new VpnView();
    BView* content = new BView("content", 0);
    fCards = new BCardLayout();
    content->SetLayout(fCards);
    fCards->AddView(fLogin);
    fCards->AddView(fTwoFactor);
    fCards->AddView(fLoading);
    fCards->AddView(fVpn);

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(menuBar)
        .Add(fNotification)
        .Add(content);
    fNotification->Hide();
    fCards->SetVisibleItem(kCardLoading);
    fLoading->SetText("Loading app...");

    float scale = be_plain_font->Size() / 12.0f;
    SetSizeLimits(380 * scale, B_SIZE_UNLIMITED, 520 * scale, B_SIZE_UNLIMITED);
}


bool MainWindow::QuitRequested()
{
    // With the tray icon the window only hides; otherwise closing it quits.
    if (BDeskbar().HasItem("Proton VPN")) {
        if (!IsHidden())
            Hide();
    } else {
        be_app->PostMessage(B_QUIT_REQUESTED);
    }
    return false;
}


void MainWindow::MenusBeginning()
{
    bool vpn = ShowingVpn();
    fSettingsItem->SetEnabled(vpn);
    fSignOutItem->SetEnabled(vpn);
    fConnectItem->SetEnabled(vpn && fStatus.state == pvpn::VpnState::Disconnected);
    fDisconnectItem->SetEnabled(vpn && fStatus.state != pvpn::VpnState::Disconnected);
    fFindItem->SetEnabled(vpn);
}


void MainWindow::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgFocusSearch:
            if (ShowingVpn())
                fVpn->FocusSearch();
            break;
        case kMsgSearchInvoked: {
            int32 kind = message->GetInt32("kind", kRowCountry);
            BString code = message->GetString("code", "");
            if (kind == kRowServer) {
                BMessage connect(kMsgConnectServer);
                connect.AddString("name", message->GetString("name", ""));
                be_app->PostMessage(&connect);
                fVpn->ClearSearch();
                fVpn->FocusSearch();
            } else {
                fVpn->ClearSearch();
                fVpn->List()->Reveal(code.String(), message->GetString("location", ""));
            }
            break;
        }
        case kMsgLogin:
        case kMsgSubmitTwoFactor:
        case kMsgCancelTwoFactor:
        case kMsgQuickConnect:
        case kMsgDisconnect:
        case kMsgConnectCountry:
        case kMsgConnectLocation:
        case kMsgConnectSecureCore:
        case kMsgConnectServer:
        case kMsgChangeServer:
        case kMsgOpenUrl:
        case kMsgDisableKillSwitch:
            if (message->what == kMsgLogin)
                fLogin->SetBusy(true);
            else if (message->what == kMsgSubmitTwoFactor)
                fTwoFactor->SetBusy(true);
            else if (message->what == kMsgChangeServer)
                fVpn->ChangeServerStarted();
            be_app->PostMessage(message);
            break;
        default:
            BWindow::MessageReceived(message);
    }
}


void MainWindow::ShowLogin(bool killSwitchBlocking)
{
    fLogin->Reset();
    fLogin->SetKillSwitchBlocking(killSwitchBlocking);
    fCards->SetVisibleItem(kCardLogin);
    fLogin->Reset();
}


void MainWindow::ShowTwoFactor()
{
    fNotification->Dismiss();
    fTwoFactor->Reset();
    fCards->SetVisibleItem(kCardTwoFactor);
    fTwoFactor->Reset();
}


void MainWindow::ShowLoading(const char* text)
{
    fLoading->SetText(text);
    fCards->SetVisibleItem(kCardLoading);
}


void MainWindow::ShowVpn()
{
    fCards->SetVisibleItem(kCardVpn);
}


bool MainWindow::ShowingVpn() const
{
    return fCards->VisibleIndex() == kCardVpn;
}


void MainWindow::Notify(const char* text, NotificationKind kind, bigtime_t duration)
{
    fNotification->Show(text, kind, duration);
}


void MainWindow::LoginFinished(bool success)
{
    fLogin->SetBusy(false);
}


void MainWindow::TwoFactorFinished(bool success)
{
    fTwoFactor->SetBusy(false);
}


void MainWindow::SetKillSwitchBlocking(bool blocking)
{
    fLogin->SetKillSwitchBlocking(blocking);
}


void MainWindow::SetStatus(const pvpn::VpnStatus& status)
{
    fStatus = status;
    fVpn->SetStatus(status);
}


void MainWindow::SetServers(std::shared_ptr<const pvpn::ServerList> servers, int userTier,
    bool rescope, const pvpn::ClientConfig& config)
{
    fVpn->SetServers(servers, userTier, rescope, config);
}
