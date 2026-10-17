// The server list: countries that expand into locations (cities or states)
// and a "Via Secure Core" group, which expand into servers, as the GTK app's
// city view shows them. Hovering a row shows its Connect (or Upgrade) button;
// clicking elsewhere on a row opens or closes it. Also the search results
// panel with its Countries / Locations / Servers sections.
#pragma once
#include "core/ServerList.h"
#include <ListView.h>
#include <OutlineListView.h>
#include <memory>
#include <set>
#include <string>

enum RowKind {
    kRowCountry,
    kRowLocation,
    kRowSecureCoreGroup,
    kRowServer,
};

class ServerRow : public BListItem {
public:
    ServerRow(RowKind kind, uint32 level);

    void DrawItem(BView* owner, BRect frame, bool complete) override;
    void Update(BView* owner, const BFont* font) override;

    // The Connect/Upgrade button within a row's frame.
    BRect ButtonRect(BView* owner, BRect frame) const;
    // The message the row's button sends.
    BMessage* ActionMessage() const;
    std::string ExpansionKey() const;

    RowKind kind;
    std::string countryCode;
    std::string label;          // country, location or server name
    std::string location;       // for servers and locations
    std::string serverId;
    std::string entryCountry;   // Secure Core servers
    uint32 features = 0;
    bool free = false;
    bool maintenance = false;
    bool smartRouting = false;
    bool upgrade = false;
    int load = -1;
    bool hovered = false;
};

class ServerListView : public BOutlineListView {
public:
    ServerListView();

    // Shows a server list for a user tier; rescope: the FreeRescope rules.
    // Keeps open rows open and updates loads in place when only they changed.
    void SetServers(std::shared_ptr<const pvpn::ServerList> servers, int userTier, bool rescope);
    int32 CountryCount() const { return fCountries; }
    // Scrolls to and selects a country (opening it to show a location).
    void Reveal(const std::string& countryCode, const std::string& location = "");

    void AttachedToWindow() override;
    void MouseDown(BPoint where) override;
    void MouseMoved(BPoint where, uint32 transit, const BMessage* message) override;
    void KeyDown(const char* bytes, int32 count) override;
    void Expand(BListItem* item) override;
    void Collapse(BListItem* item) override;
    bool InitiateDrag(BPoint point, int32 index, bool wasSelected) override { return false; }

private:
    void Rebuild(const pvpn::ServerList& servers, int userTier, bool rescope);
    void UpdateLoads(const pvpn::ServerList& servers);
    void SetHovered(int32 index);
    void Activate(ServerRow* row);

    std::shared_ptr<const pvpn::ServerList> fServers;
    std::set<std::string> fExpanded;
    std::string fSignature;     // the structure the rows were built from
    int fTier = -1;
    bool fRescope = false;
    int32 fCountries = 0;
    int32 fHovered = -1;
};

class SearchResultsView : public BListView {
public:
    SearchResultsView();

    void Search(const std::string& text, std::shared_ptr<const pvpn::ServerList> servers,
        int userTier, bool rescope);
    void MouseDown(BPoint where) override;
    void KeyDown(const char* bytes, int32 count) override;

private:
    void Activate(int32 index);
};
