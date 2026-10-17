// The signed-in screen: connection status, the Connect / Disconnect / Cancel
// Connection button (and Change server for free plans with FreeRescope), the
// search field, and the server list or search results.
#pragma once
#include "core/Account.h"
#include "core/Connector.h"
#include "core/ServerList.h"
#include <View.h>
#include <memory>
#include <string>

class BButton;
class BCardLayout;
class BMessageRunner;
class BStringView;
class BTextControl;
class SearchResultsView;
class ServerListView;
class StatusView;

class VpnView : public BView {
public:
    VpnView();
    ~VpnView() override;

    void AttachedToWindow() override;
    void MessageReceived(BMessage* message) override;

    void SetStatus(const pvpn::VpnStatus& status);
    void SetServers(std::shared_ptr<const pvpn::ServerList> servers, int userTier, bool rescope,
        const pvpn::ClientConfig& config);
    void FocusSearch();
    void ClearSearch();
    ServerListView* List() const { return fList; }

    // Change server (free plans): a random server, then a cooldown.
    bool ChangeServerAvailable() const;
    void ChangeServerStarted();

private:
    void UpdateButtons();
    void ShowLegend();

    StatusView* fStatusView;
    BButton* fConnect;
    BButton* fChangeServer;
    BStringView* fCooldownNote;
    BTextControl* fSearch;
    BStringView* fCount;
    BButton* fLegend;
    BCardLayout* fCards;
    BView* fListCard;
    BView* fResultsCard;
    ServerListView* fList;
    SearchResultsView* fResults;

    pvpn::VpnStatus fStatus;
    std::shared_ptr<const pvpn::ServerList> fServers;
    int fTier = 0;
    bool fRescope = false;
    pvpn::ClientConfig fConfig;
    // Change server cooldown.
    int fChanges = 0;
    double fCooldownUntil = 0;
    bool fLongCooldown = false;
    bool fChangePending = false;
    double fConnectingSince = 0;
    BMessageRunner* fTicker = nullptr;
};
