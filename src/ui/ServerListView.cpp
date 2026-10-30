#include "ServerListView.h"
#include "Icons.h"
#include "Messages.h"
#include "Widgets.h"
#include "core/Countries.h"
#include "core/Util.h"
#include <Font.h>
#include <ScrollBar.h>
#include <Window.h>
#include <algorithm>
#include <cmath>
#include <functional>

using namespace pvpn;

namespace {

const char kUpgradeUrl[] = "https://account.protonvpn.com/";

float Scaled(float value)
{
    return roundf(value * Icons::Scale());
}

rgb_color LoadColor(int load)
{
    if (load > 90)
        return DangerColor();
    if (load > 75)
        return WarningColor();
    return SuccessColor();
}

std::string LoadText(int load)
{
    return std::to_string(std::max(0, std::min(load, 100))) + "%";
}

}  // namespace


ServerRow::ServerRow(RowKind kind_, uint32 level)
    :
    BListItem(level, false),
    kind(kind_)
{
}


void ServerRow::Update(BView* owner, const BFont* font)
{
    BListItem::Update(owner, font);
    font_height height;
    font->GetHeight(&height);
    float text = ceilf(height.ascent + height.descent);
    SetHeight(std::max(text, Scaled(16)) + Scaled(12));
}


BRect ServerRow::ButtonRect(BView* owner, BRect frame) const
{
    float width = owner->StringWidth("Upgrade") + Scaled(20);
    float inset = Scaled(5);
    return BRect(frame.right - inset - width, frame.top + inset, frame.right - inset,
        frame.bottom - inset);
}


std::string ServerRow::ExpansionKey() const
{
    switch (kind) {
        case kRowCountry:
            return "C:" + countryCode;
        case kRowLocation:
            return "L:" + countryCode + ":" + label;
        case kRowSecureCoreGroup:
            return "S:" + countryCode;
        default:
            return "";
    }
}


BMessage* ServerRow::ActionMessage() const
{
    if (upgrade) {
        BMessage* message = new BMessage(kMsgOpenUrl);
        message->AddString("url", kUpgradeUrl);
        return message;
    }
    BMessage* message = nullptr;
    switch (kind) {
        case kRowCountry:
            message = new BMessage(kMsgConnectCountry);
            break;
        case kRowLocation:
            message = new BMessage(kMsgConnectLocation);
            message->AddString("location", label.c_str());
            break;
        case kRowSecureCoreGroup:
            message = new BMessage(kMsgConnectSecureCore);
            break;
        case kRowServer:
            message = new BMessage(kMsgConnectServer);
            message->AddString("name", serverId.empty() ? label.c_str() : location.c_str());
            message->AddString("id", serverId.c_str());
            break;
    }
    message->AddString("code", countryCode.c_str());
    return message;
}


void ServerRow::DrawItem(BView* owner, BRect frame, bool complete)
{
    bool selected = IsSelected();
    rgb_color background = ui_color(B_LIST_BACKGROUND_COLOR);
    if (selected)
        background = ui_color(B_LIST_SELECTED_BACKGROUND_COLOR);
    else if (hovered)
        background = Icons::Mix(background, ui_color(B_LIST_SELECTED_BACKGROUND_COLOR), 0.35f);
    owner->SetLowColor(background);
    owner->FillRect(frame, B_SOLID_LOW);

    rgb_color text = ui_color(selected ? B_LIST_SELECTED_ITEM_TEXT_COLOR : B_LIST_ITEM_TEXT_COLOR);
    bool dim = (maintenance && !upgrade) || upgrade;
    rgb_color weak = Icons::Mix(text, background, 0.45f);
    rgb_color iconColor = Icons::Mix(text, background, 0.3f);

    float x = frame.left + Scaled(4);
    float middle = floorf((frame.top + frame.bottom) / 2);
    BRect icon(0, 0, Scaled(24) - 1, Scaled(16) - 1);
    icon.OffsetTo(x, middle - floorf(icon.Height() / 2));
    switch (kind) {
        case kRowCountry:
            Icons::DrawFlag(owner, countryCode, icon);
            break;
        case kRowLocation: {
            BRect pin(0, 0, Scaled(16) - 1, Scaled(16) - 1);
            pin.OffsetTo(icon.left + Scaled(4), icon.top);
            Icons::Draw(owner, Icons::Tinted("location", iconColor), pin);
            break;
        }
        case kRowSecureCoreGroup: {
            BRect sc(0, 0, Scaled(16) - 1, Scaled(16) - 1);
            sc.OffsetTo(icon.left + Scaled(4), icon.top);
            Icons::Draw(owner, Icons::Tinted("secure-core", iconColor), sc);
            break;
        }
        case kRowServer:
            if (!entryCountry.empty())
                Icons::DrawDoubleFlag(owner, countryCode, entryCountry, icon);
            break;
    }
    x = icon.right + Scaled(8);

    // Right side, from the edge inwards.
    float right = frame.right - Scaled(6);
    font_height height;
    owner->GetFontHeight(&height);
    float baseline = floorf(middle + (height.ascent - height.descent) / 2);
    if (hovered || selected) {
        BRect button = ButtonRect(owner, frame);
        rgb_color accent = upgrade ? WeakTextColor() : AccentColor();
        owner->SetHighColor(Icons::Mix(background, accent, selected ? 0.5f : 0.25f));
        owner->FillRoundRect(button, Scaled(4), Scaled(4));
        owner->SetHighColor(accent);
        owner->StrokeRoundRect(button, Scaled(4), Scaled(4));
        const char* action = upgrade ? "Upgrade" : "Connect";
        owner->SetHighColor(selected ? text : ui_color(B_LIST_ITEM_TEXT_COLOR));
        owner->SetLowColor(Icons::Mix(background, accent, selected ? 0.5f : 0.25f));
        owner->DrawString(action, BPoint(button.left + (button.Width() - owner->StringWidth(action)) / 2,
            baseline));
        owner->SetLowColor(background);
        right = button.left - Scaled(8);
    } else if (maintenance && !upgrade) {
        BRect wrench(right - Scaled(16) + 1, middle - Scaled(8), right, middle + Scaled(8) - 1);
        Icons::Draw(owner, Icons::Tinted("maintenance", iconColor), wrench);
        right = wrench.left - Scaled(8);
    } else if (kind == kRowServer && load >= 0) {
        std::string percent = LoadText(load);
        float width = owner->StringWidth("100%");
        owner->SetHighColor(dim ? weak : text);
        owner->DrawString(percent.c_str(), BPoint(right - owner->StringWidth(percent.c_str()), baseline));
        right -= width + Scaled(6);
        BRect bar(right - Scaled(36) + 1, middle - Scaled(2), right, middle + Scaled(2));
        owner->SetHighColor(Icons::Mix(background, text, 0.15f));
        owner->FillRoundRect(bar, 2, 2);
        BRect filled = bar;
        filled.right = bar.left + (bar.Width()) * std::min(load, 100) / 100.0f;
        owner->SetHighColor(LoadColor(load));
        owner->FillRoundRect(filled, 2, 2);
        right = bar.left - Scaled(8);
    }

    // Feature icons, left to right: Tor, P2P, Smart routing, Secure Core.
    if (!(hovered || selected) || kind != kRowServer) {
        struct Feature {
            bool shown;
            const char* icon;
        };
        Feature items[] = {
            {kind != kRowSecureCoreGroup && kind != kRowServer && (features & kFeatureSecureCore) != 0,
                "secure-core"},
            {smartRouting, "smart-routing"},
            {(features & kFeatureP2P) != 0, "p2p"},
            {(features & kFeatureTor) != 0, "tor"},
        };
        float size = Scaled(16);
        for (const Feature& feature : items) {
            if (!feature.shown)
                continue;
            BRect area(right - size + 1, middle - size / 2, right, middle + size / 2 - 1);
            if (area.left <= x + owner->StringWidth(label.c_str()))
                break;
            Icons::Draw(owner, Icons::Tinted(feature.icon, dim ? weak : iconColor), area);
            right = area.left - Scaled(4);
        }
    }

    owner->SetHighColor(dim ? weak : text);
    BString name(label.c_str());
    owner->TruncateString(&name, B_TRUNCATE_END, std::max(0.0f, right - x));
    owner->DrawString(name.String(), BPoint(x, baseline));
}


ServerListView::ServerListView()
    :
    BOutlineListView("servers", B_SINGLE_SELECTION_LIST)
{
}


void ServerListView::AttachedToWindow()
{
    BOutlineListView::AttachedToWindow();
    SetFlags(Flags() | B_FULL_UPDATE_ON_RESIZE);
}


void ServerListView::FrameResized(float width, float height)
{
    BOutlineListView::FrameResized(width, height);
    // The notification bar moves the list; redraw all rows, not copied bits.
    Invalidate();
}


void ServerListView::SetServers(std::shared_ptr<const ServerList> servers, int userTier,
    bool rescope)
{
    if (!servers)
        return;
    // The structure: countries, locations and server ids in display order.
    std::string signature = std::to_string(userTier) + (rescope ? "r" : "n");
    std::vector<CountryGroup> countries = servers->GroupByCountry(userTier);
    for (const CountryGroup& country : countries) {
        signature += "|" + country.code;
        for (const LocationGroup& location : country.locations) {
            signature += "/" + location.name;
            for (const LogicalServer* server : location.servers)
                signature += "," + server->id;
        }
        for (const LogicalServer* server : country.secureCore)
            signature += ";" + server->id;
    }
    fServers = servers;
    if (signature == fSignature && FullListCountItems() > 0) {
        UpdateLoads(*servers);
        return;
    }
    fSignature = signature;
    Rebuild(*servers, userTier, rescope);
}


void ServerListView::Rebuild(const ServerList& servers, int userTier, bool rescope)
{
    fTier = userTier;
    fRescope = rescope;
    float scroll = ScrollBar(B_VERTICAL) != nullptr ? ScrollBar(B_VERTICAL)->Value() : 0;
    std::string selectedKey;
    if (ServerRow* selected = static_cast<ServerRow*>(ItemAt(CurrentSelection())))
        selectedKey = selected->ExpansionKey().empty() ? "V:" + selected->serverId
            : selected->ExpansionKey();
    fHovered = -1;
    // Remember which rows are open (by country, location or group).
    std::set<std::string> expanded;
    std::vector<BListItem*> old;
    for (int32 i = 0; i < FullListCountItems(); i++) {
        BListItem* item = FullListItemAt(i);
        old.push_back(item);
        if (item->IsExpanded()) {
            std::string key = static_cast<ServerRow*>(item)->ExpansionKey();
            if (!key.empty())
                expanded.insert(key);
        }
    }
    MakeEmpty();
    for (BListItem* item : old)
        delete item;

    bool freeUser = userTier == kTierFree;
    auto upgradeFor = [&](RowKind kind, bool free) {
        if (!freeUser)
            return false;
        if (rescope)
            return kind == kRowCountry ? !free : true;
        return !free;
    };
    std::vector<CountryGroup> countries = servers.GroupByCountry(userTier);
    fCountries = countries.size();
    std::vector<BListItem*> toExpand;
    BListItem* reselect = nullptr;
    for (const CountryGroup& country : countries) {
        ServerRow* row = new ServerRow(kRowCountry, 0);
        row->countryCode = country.code;
        row->label = country.name;
        row->features = country.summary.features;
        row->free = country.summary.free;
        row->maintenance = country.summary.underMaintenance;
        row->smartRouting = country.summary.smartRouting;
        row->upgrade = upgradeFor(kRowCountry, row->free);
        AddItem(row, FullListCountItems());
        if (expanded.count(row->ExpansionKey()))
            toExpand.push_back(row);
        if (row->ExpansionKey() == selectedKey)
            reselect = row;
        auto addServer = [&](ServerRow* parent, const LogicalServer* server, bool secureCore) {
            ServerRow* item = new ServerRow(kRowServer, 2);
            item->countryCode = country.code;
            item->serverId = server->id;
            item->location = server->name;
            item->label = secureCore ? "Via " + CountryName(server->entryCountry) : server->name;
            item->entryCountry = secureCore ? server->entryCountry : "";
            item->features = server->features;
            item->free = server->Free();
            item->maintenance = !server->Enabled();
            item->smartRouting = server->SmartRouting();
            item->load = server->load;
            item->upgrade = upgradeFor(kRowServer, item->free);
            // In display order: the item's outline level makes it a child of
            // the row before it (AddUnder would put it first).
            AddItem(item, FullListCountItems());
            if ("V:" + server->id == selectedKey)
                reselect = item;
        };
        for (const LocationGroup& location : country.locations) {
            ServerRow* locationRow = new ServerRow(kRowLocation, 1);
            locationRow->countryCode = country.code;
            locationRow->label = location.name;
            locationRow->features = location.summary.features;
            locationRow->free = location.summary.free;
            locationRow->maintenance = location.summary.underMaintenance;
            locationRow->smartRouting = location.summary.smartRouting;
            locationRow->upgrade = upgradeFor(kRowLocation, locationRow->free);
            AddItem(locationRow, FullListCountItems());
            if (expanded.count(locationRow->ExpansionKey()))
                toExpand.push_back(locationRow);
            if (locationRow->ExpansionKey() == selectedKey)
                reselect = locationRow;
            for (const LogicalServer* server : location.servers)
                addServer(locationRow, server, false);
        }
        if (!country.secureCore.empty()) {
            ServerRow* group = new ServerRow(kRowSecureCoreGroup, 1);
            group->countryCode = country.code;
            group->label = "Via Secure Core";
            group->features = kFeatureSecureCore;
            group->free = country.secureCoreSummary.free;
            group->maintenance = country.secureCoreSummary.underMaintenance;
            group->upgrade = upgradeFor(kRowSecureCoreGroup, group->free);
            AddItem(group, FullListCountItems());
            if (expanded.count(group->ExpansionKey()))
                toExpand.push_back(group);
            for (const LogicalServer* server : country.secureCore)
                addServer(group, server, true);
        }
    }
    // Rows start closed; open the ones that were open, outermost first.
    for (int32 i = 0; i < FullListCountItems(); i++) {
        BListItem* item = FullListItemAt(i);
        if (item->IsExpanded())
            BOutlineListView::Collapse(item);
    }
    for (BListItem* item : toExpand)
        BOutlineListView::Expand(item);
    if (reselect != nullptr && IndexOf(reselect) >= 0)
        Select(IndexOf(reselect));
    if (ScrollBar(B_VERTICAL) != nullptr)
        ScrollBar(B_VERTICAL)->SetValue(scroll);
}


void ServerListView::UpdateLoads(const ServerList& servers)
{
    // Same structure: refresh what loads updates change, in place.
    for (int32 i = 0; i < FullListCountItems(); i++) {
        ServerRow* row = static_cast<ServerRow*>(FullListItemAt(i));
        if (row->kind != kRowServer)
            continue;
        const LogicalServer* server = servers.ById(row->serverId);
        if (server == nullptr)
            continue;
        row->load = server->load;
        row->maintenance = !server->Enabled();
    }
    // Group maintenance follows its servers.
    std::vector<CountryGroup> countries = servers.GroupByCountry(fTier);
    std::map<std::string, const CountryGroup*> byCode;
    for (const CountryGroup& country : countries)
        byCode[country.code] = &country;
    for (int32 i = 0; i < FullListCountItems(); i++) {
        ServerRow* row = static_cast<ServerRow*>(FullListItemAt(i));
        auto it = byCode.find(row->countryCode);
        if (it == byCode.end())
            continue;
        const CountryGroup& country = *it->second;
        if (row->kind == kRowCountry)
            row->maintenance = country.summary.underMaintenance;
        else if (row->kind == kRowSecureCoreGroup)
            row->maintenance = country.secureCoreSummary.underMaintenance;
        else if (row->kind == kRowLocation) {
            for (const LocationGroup& location : country.locations) {
                if (location.name == row->label)
                    row->maintenance = location.summary.underMaintenance;
            }
        }
    }
    Invalidate();
}


void ServerListView::Reveal(const std::string& countryCode, const std::string& location)
{
    ServerRow* target = nullptr;
    for (int32 i = 0; i < FullListCountItems(); i++) {
        ServerRow* row = static_cast<ServerRow*>(FullListItemAt(i));
        if (row->countryCode != countryCode)
            continue;
        if (row->kind == kRowCountry && location.empty()) {
            target = row;
            break;
        }
        if (row->kind == kRowCountry && !row->IsExpanded())
            BOutlineListView::Expand(row);
        if (row->kind == kRowLocation && row->label == location) {
            target = row;
            break;
        }
    }
    if (target == nullptr)
        return;
    int32 index = IndexOf(target);
    if (index < 0)
        return;
    Select(index);
    ScrollToSelection();
    MakeFocus(true);
}


void ServerListView::SetHovered(int32 index)
{
    if (index == fHovered)
        return;
    if (ServerRow* old = static_cast<ServerRow*>(ItemAt(fHovered))) {
        old->hovered = false;
        InvalidateItem(fHovered);
    }
    fHovered = index;
    if (ServerRow* row = static_cast<ServerRow*>(ItemAt(fHovered))) {
        row->hovered = true;
        InvalidateItem(fHovered);
    }
}


void ServerListView::MouseMoved(BPoint where, uint32 transit, const BMessage* message)
{
    BOutlineListView::MouseMoved(where, transit, message);
    if (transit == B_EXITED_VIEW || transit == B_OUTSIDE_VIEW)
        SetHovered(-1);
    else
        SetHovered(IndexOf(where));
}


void ServerListView::Activate(ServerRow* row)
{
    if (row == nullptr || (row->maintenance && !row->upgrade))
        return;
    BMessage* message = row->ActionMessage();
    Window()->PostMessage(message);
    delete message;
}


void ServerListView::MouseDown(BPoint where)
{
    int32 index = IndexOf(where);
    ServerRow* row = static_cast<ServerRow*>(ItemAt(index));
    if (row == nullptr) {
        BOutlineListView::MouseDown(where);
        return;
    }
    BRect frame = ItemFrame(index);
    BRect latch = LatchRect(frame, row->OutlineLevel());
    if (latch.Contains(where)) {
        BOutlineListView::MouseDown(where);
        return;
    }
    MakeFocus(true);
    Select(index);
    if (row->ButtonRect(this, frame).Contains(where)) {
        Activate(row);
        return;
    }
    if (row->kind != kRowServer) {
        if (row->IsExpanded())
            Collapse(row);
        else
            Expand(row);
    }
}


void ServerListView::KeyDown(const char* bytes, int32 count)
{
    if (count == 1 && (bytes[0] == B_ENTER || bytes[0] == B_SPACE)) {
        Activate(static_cast<ServerRow*>(ItemAt(CurrentSelection())));
        return;
    }
    BOutlineListView::KeyDown(bytes, count);
}


// --- Search results ----------------------------------------------------------------

namespace {

enum ResultKind {
    kResultHeader,
    kResultCountry,
    kResultLocation,
    kResultServer,
    kResultMore,
};

class ResultItem : public BListItem {
public:
    ResultItem(ResultKind kind_, const std::string& label_) : kind(kind_), label(label_) {}

    void Update(BView* owner, const BFont* font) override
    {
        BListItem::Update(owner, font);
        font_height height;
        font->GetHeight(&height);
        SetHeight(ceilf(height.ascent + height.descent) + Scaled(kind == kResultHeader ? 10 : 8));
    }

    void DrawItem(BView* owner, BRect frame, bool complete) override
    {
        bool selected = IsSelected() && kind != kResultHeader && kind != kResultMore;
        rgb_color background = ui_color(selected ? B_LIST_SELECTED_BACKGROUND_COLOR
            : B_LIST_BACKGROUND_COLOR);
        owner->SetLowColor(background);
        owner->FillRect(frame, B_SOLID_LOW);
        rgb_color text = ui_color(selected ? B_LIST_SELECTED_ITEM_TEXT_COLOR : B_LIST_ITEM_TEXT_COLOR);
        font_height height;
        owner->GetFontHeight(&height);
        float baseline = floorf((frame.top + frame.bottom) / 2 + (height.ascent - height.descent) / 2);
        float x = frame.left + Scaled(kind == kResultHeader ? 4 : 12);
        if (kind == kResultHeader) {
            owner->SetFont(be_bold_font);
            owner->SetHighColor(Icons::Mix(text, background, 0.25f));
            owner->DrawString(label.c_str(), BPoint(x, baseline));
            if (!detail.empty())
                owner->DrawString(detail.c_str(),
                    BPoint(frame.right - Scaled(8) - owner->StringWidth(detail.c_str()), baseline));
            owner->SetFont(be_plain_font);
            return;
        }
        if (kind == kResultCountry) {
            BRect flag(0, 0, Scaled(24) - 1, Scaled(16) - 1);
            flag.OffsetTo(x, floorf((frame.top + frame.bottom) / 2 - flag.Height() / 2));
            Icons::DrawFlag(owner, code, flag);
            x = flag.right + Scaled(8);
        }
        owner->SetHighColor(kind == kResultMore ? Icons::Mix(text, background, 0.4f) : text);
        owner->DrawString(label.c_str(), BPoint(x, baseline));
        if (!detail.empty()) {
            owner->SetHighColor(Icons::Mix(text, background, 0.4f));
            owner->DrawString(detail.c_str(),
                BPoint(frame.right - Scaled(8) - owner->StringWidth(detail.c_str()), baseline));
        }
    }

    ResultKind kind;
    std::string label;
    std::string detail;     // load or a header's right-hand label
    std::string code;
    std::string location;
    std::string name;
};

const size_t kMaxResults = 100;

}  // namespace


SearchResultsView::SearchResultsView()
    :
    BListView("search results", B_SINGLE_SELECTION_LIST)
{
}


void SearchResultsView::Search(const std::string& text, std::shared_ptr<const ServerList> servers,
    int userTier, bool rescope)
{
    for (int32 i = CountItems() - 1; i >= 0; i--)
        delete RemoveItem(i);
    if (!servers || Trim(text).empty())
        return;
    std::string needle = Trim(text);

    std::vector<CountryGroup> countries = servers->GroupByCountry(userTier);
    std::vector<ResultItem*> countryRows, locationRows, serverRows;
    std::set<std::string> seenLocations;
    std::vector<const LogicalServer*> matchingServers;
    for (const CountryGroup& country : countries) {
        if (FoldedContains(country.name, needle) && !country.summary.underMaintenance) {
            ResultItem* item = new ResultItem(kResultCountry, country.name);
            item->code = country.code;
            countryRows.push_back(item);
        }
        for (const LocationGroup& location : country.locations) {
            if (!FoldedContains(location.name, needle) || location.summary.underMaintenance)
                continue;
            std::string key = country.code + ":" + location.name;
            if (seenLocations.insert(key).second) {
                ResultItem* item = new ResultItem(kResultLocation, location.name + ", " + country.name);
                item->code = country.code;
                item->location = location.name;
                locationRows.push_back(item);
            }
        }
        if (rescope)
            continue;
        for (const LogicalServer* server : country.servers) {
            if (server->tier <= userTier && server->Enabled() && FoldedContains(server->name, needle))
                matchingServers.push_back(server);
        }
    }
    std::sort(locationRows.begin(), locationRows.end(), [](ResultItem* a, ResultItem* b) {
        return FoldForSearch(a->label) < FoldForSearch(b->label);
    });
    std::sort(matchingServers.begin(), matchingServers.end(),
        [](const LogicalServer* a, const LogicalServer* b) {
            std::string countryA = CountryName(a->exitCountry), countryB = CountryName(b->exitCountry);
            if (countryA != countryB)
                return countryA < countryB;
            return NaturalLess(a->name, b->name);
        });
    for (const LogicalServer* server : matchingServers) {
        ResultItem* item = new ResultItem(kResultServer, server->name);
        item->detail = LoadText(server->load);
        item->code = server->exitCountry;
        item->name = server->name;
        serverRows.push_back(item);
    }

    auto addSection = [this](const char* title, std::vector<ResultItem*>& rows, const char* detail) {
        if (rows.empty())
            return;
        ResultItem* header = new ResultItem(kResultHeader,
            std::string(title) + " (" + std::to_string(rows.size()) + ")");
        if (detail != nullptr)
            header->detail = detail;
        AddItem(header);
        for (size_t i = 0; i < rows.size(); i++) {
            if (i < kMaxResults)
                AddItem(rows[i]);
            else
                delete rows[i];
        }
        if (rows.size() > kMaxResults)
            AddItem(new ResultItem(kResultMore, "..."));
    };
    addSection("Countries", countryRows, nullptr);
    addSection("Locations", locationRows, nullptr);
    addSection("Servers", serverRows, "Server load");
    if (CountItems() == 0)
        AddItem(new ResultItem(kResultMore, "No results found"));
}


void SearchResultsView::Activate(int32 index)
{
    ResultItem* item = static_cast<ResultItem*>(ItemAt(index));
    if (item == nullptr || item->kind == kResultHeader || item->kind == kResultMore)
        return;
    BMessage message(kMsgSearchInvoked);
    message.AddInt32("kind", item->kind == kResultServer ? kRowServer
        : item->kind == kResultLocation ? kRowLocation : kRowCountry);
    message.AddString("code", item->code.c_str());
    message.AddString("location", item->location.c_str());
    message.AddString("name", item->name.c_str());
    Window()->PostMessage(&message);
}


void SearchResultsView::MouseDown(BPoint where)
{
    BListView::MouseDown(where);
    Activate(IndexOf(where));
}


void SearchResultsView::KeyDown(const char* bytes, int32 count)
{
    if (count == 1 && bytes[0] == B_ENTER) {
        Activate(CurrentSelection());
        return;
    }
    BListView::KeyDown(bytes, count);
}
