#include "VpnView.h"
#include "Icons.h"
#include "Messages.h"
#include "ServerListView.h"
#include "StatusView.h"
#include "Widgets.h"
#include "core/Util.h"
#include <Alert.h>
#include <Button.h>
#include <CardLayout.h>
#include <ControlLook.h>
#include <LayoutBuilder.h>
#include <MessageRunner.h>
#include <ScrollView.h>
#include <StringView.h>
#include <TextControl.h>
#include <Window.h>
#include <cmath>

using namespace pvpn;

namespace {

const uint32 kMsgShowLegend = 'lgnd';

const char kLegendText[] =
    "Smart routing\n"
    "This technology allows Proton VPN to provide higher speed and security in "
    "difficult-to-reach countries.\n\n"
    "Secure Core\n"
    "Connect to your destination server through a second, maximum security VPN "
    "server. Slower, but more private.\n\n"
    "P2P/BitTorrent\n"
    "These servers give the best performance for BitTorrent and file sharing.\n\n"
    "Tor\n"
    "Connect to a Tor server to access hidden services and onion sites using any browser.";

}  // namespace


VpnView::VpnView()
    :
    BView("vpn", 0)
{
    float spacing = be_control_look->DefaultItemSpacing();
    fStatusView = new StatusView();
    fConnect = new BButton("connect", "Connect", new BMessage(kMsgQuickConnect));
    fConnect->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));
    fChangeServer = new BButton("change server", "Change server", new BMessage(kMsgChangeServer));
    fChangeServer->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));
    fCooldownNote = new BStringView("cooldown", "Get unlimited server changes with VPN Plus.");
    fCooldownNote->SetAlignment(B_ALIGN_CENTER);
    fSearch = new BTextControl("search", "Search:", "", new BMessage(kMsgSearchChanged));
    fSearch->SetModificationMessage(new BMessage(kMsgSearchChanged));
    fCount = new BStringView("count", "All countries");
    fLegend = new BButton("legend", "Features" B_UTF8_ELLIPSIS, new BMessage(kMsgShowLegend));
    fLegend->SetFlat(true);

    fList = new ServerListView();
    fResults = new SearchResultsView();
    fListCard = new BScrollView("list scroll", fList, 0, false, true, B_FANCY_BORDER);
    fResultsCard = new BScrollView("results scroll", fResults, 0, false, true, B_FANCY_BORDER);
    BView* cards = new BView("cards", 0);
    fCards = new BCardLayout();
    cards->SetLayout(fCards);
    fCards->AddView(fListCard);
    fCards->AddView(fResultsCard);
    fCards->SetVisibleItem((int32)0);

    BLayoutBuilder::Group<>(this, B_VERTICAL, spacing)
        .Add(fStatusView)
        .AddGroup(B_VERTICAL, spacing / 2)
            .SetInsets(spacing, 0, spacing, 0)
            .Add(fConnect)
            .Add(fChangeServer)
            .Add(fCooldownNote)
        .End()
        .AddGroup(B_VERTICAL, spacing / 2)
            .SetInsets(spacing, 0, spacing, spacing)
            .Add(fSearch)
            .AddGroup(B_HORIZONTAL)
                .Add(fCount)
                .AddGlue()
                .Add(fLegend)
            .End()
            .Add(cards, 10)
        .End();
    fChangeServer->Hide();
    fCooldownNote->Hide();
}


VpnView::~VpnView()
{
    delete fTicker;
}


void VpnView::AttachedToWindow()
{
    BView::AttachedToWindow();
    AdoptParentColors();
    fConnect->SetTarget(Window());
    fChangeServer->SetTarget(Window());
    fSearch->SetTarget(this);
    fLegend->SetTarget(this);
    fCount->SetHighColor(WeakTextColor());
    fCooldownNote->SetHighColor(WeakTextColor());
    BMessage tick(kMsgCooldownTick);
    fTicker = new BMessageRunner(BMessenger(this), &tick, 1000000);
    UpdateButtons();
}


void VpnView::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgSearchChanged: {
            std::string text = Trim(fSearch->Text());
            if (text.empty()) {
                fCards->SetVisibleItem((int32)0);
            } else {
                fResults->Search(text, fServers, fTier, fRescope);
                fCards->SetVisibleItem((int32)1);
            }
            break;
        }
        case kMsgShowLegend: {
            BAlert* alert = new BAlert("Features", kLegendText, "Close");
            alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
            alert->Go(nullptr);
            break;
        }
        case kMsgCooldownTick:
            UpdateButtons();
            break;
        default:
            BView::MessageReceived(message);
    }
}


void VpnView::SetStatus(const VpnStatus& status)
{
    VpnState previous = fStatus.state;
    fStatus = status;
    if (status.state == VpnState::Connecting && previous != VpnState::Connecting)
        fConnectingSince = MonotonicNow();
    // A finished Change server starts the cooldown.
    if (status.state == VpnState::Connected && previous != VpnState::Connected && fChangePending) {
        fChangePending = false;
        fChanges++;
        if (fChanges >= std::max(1, fConfig.changeServerAttemptLimit)) {
            fChanges = 0;
            fLongCooldown = true;
            fCooldownUntil = MonotonicNow() + fConfig.changeServerLongDelay;
        } else {
            fLongCooldown = false;
            fCooldownUntil = MonotonicNow() + fConfig.changeServerShortDelay;
        }
    }
    if (status.state == VpnState::Error || (status.state == VpnState::Disconnected && !status.reconnecting))
        fChangePending = false;
    std::vector<std::string> free = fServers ? fServers->FreeCountries() : std::vector<std::string>();
    fStatusView->SetStatus(status, fTier, fRescope, free);
    UpdateButtons();
}


void VpnView::SetServers(std::shared_ptr<const ServerList> servers, int userTier, bool rescope,
    const ClientConfig& config)
{
    fServers = servers;
    fTier = userTier;
    fRescope = rescope;
    fConfig = config;
    fList->SetServers(servers, userTier, rescope);
    BString count;
    count.SetToFormat("All countries (%d)", (int)fList->CountryCount());
    fCount->SetText(count.String());
    if (!Trim(fSearch->Text()).empty())
        fResults->Search(Trim(fSearch->Text()), fServers, fTier, fRescope);
    fStatusView->SetStatus(fStatus, fTier, fRescope,
        servers ? servers->FreeCountries() : std::vector<std::string>());
    UpdateButtons();
}


bool VpnView::ChangeServerAvailable() const
{
    if (!fRescope || fTier != kTierFree)
        return false;
    if (fStatus.state == VpnState::Connecting && MonotonicNow() - fConnectingSince >= 8)
        return true;   // a stuck attempt may always move on
    return fStatus.state == VpnState::Connected && MonotonicNow() >= fCooldownUntil;
}


void VpnView::ChangeServerStarted()
{
    fChangePending = fStatus.state == VpnState::Connected;
}


void VpnView::UpdateButtons()
{
    switch (fStatus.state) {
        case VpnState::Disconnected:
            if (!fStatus.reconnecting) {
                fConnect->SetLabel("Connect");
                fConnect->SetMessage(new BMessage(kMsgQuickConnect));
                StyleButton(fConnect, AccentColor());
            }
            break;
        case VpnState::Connecting:
        case VpnState::Error:
            fConnect->SetLabel("Cancel Connection");
            fConnect->SetMessage(new BMessage(kMsgDisconnect));
            StyleButton(fConnect, DangerColor());
            break;
        case VpnState::Connected:
            fConnect->SetLabel("Disconnect");
            fConnect->SetMessage(new BMessage(kMsgDisconnect));
            StyleButton(fConnect, DangerColor());
            break;
        case VpnState::Disconnecting:
            break;
    }
    bool showChange = fRescope && fTier == kTierFree
        && (fStatus.state == VpnState::Connected || fStatus.state == VpnState::Connecting);
    SetVisible(fChangeServer, showChange);
    double remaining = fCooldownUntil - MonotonicNow();
    bool cooling = showChange && remaining > 0;
    if (cooling) {
        int seconds = (int)ceil(remaining);
        BString label;
        label.SetToFormat("Change server  %02d:%02d", seconds / 60, seconds % 60);
        fChangeServer->SetLabel(label.String());
        fCooldownNote->SetText(fLongCooldown
            ? "You've reached the maximum number of free server changes for now. "
              "Get unlimited server changes with VPN Plus."
            : "Get unlimited server changes with VPN Plus.");
    } else {
        fChangeServer->SetLabel("Change server");
    }
    fChangeServer->SetEnabled(ChangeServerAvailable());
    SetVisible(fCooldownNote, cooling);
}


void VpnView::FocusSearch()
{
    fSearch->MakeFocus(true);
}


void VpnView::ClearSearch()
{
    fSearch->SetText("");
    fCards->SetVisibleItem((int32)0);
}
