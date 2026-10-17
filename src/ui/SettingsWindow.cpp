#include "SettingsWindow.h"
#include "App.h"
#include "Icons.h"
#include "Messages.h"
#include "Widgets.h"
#include "core/Util.h"
#include <Alert.h>
#include <Box.h>
#include <Button.h>
#include <CheckBox.h>
#include <ControlLook.h>
#include <Invoker.h>
#include <LayoutBuilder.h>
#include <ListView.h>
#include <MenuField.h>
#include <MenuItem.h>
#include <PopUpMenu.h>
#include <RadioButton.h>
#include <ScrollView.h>
#include <SeparatorView.h>
#include <StringView.h>
#include <TextControl.h>
#include <thread>

using namespace pvpn;

namespace {

enum {
    kMsgNetShield = 'sens',
    kMsgKillSwitch = 'seks',
    kMsgKillMode = 'sekm',
    kMsgPortForwarding = 'sepf',
    kMsgProtocol = 'sepr',
    kMsgAccelerator = 'seva',
    kMsgModerateNat = 'semn',
    kMsgIpv6 = 'se6',
    kMsgCustomDns = 'secd',
    kMsgAddDns = 'sead',
    kMsgRemoveDns = 'serd',
    kMsgAutoConnect = 'seac',
    kMsgStartMinimized = 'sesm',
    kMsgTrayPins = 'setp',
    kMsgCrashReports = 'secr',
    kMsgUpgrade = 'seup',
    kMsgManageAccount = 'sema',
    kMsgNetShieldConfirmed = 'senc',
    kMsgCustomDnsConfirmed = 'sedc',
};

const char kReconnectText[] = "Please establish a new VPN connection for changes to take effect.";
const char kPricingUrl[] = "https://protonvpn.com/pricing";

const char* const kNetShieldLabels[] = {
    "Off",
    "Block Malware",
    "Block ads, trackers and malware",
};

struct ProtocolChoice {
    const char* key;
    const char* title;
};

const ProtocolChoice kProtocols[] = {
    {"wireguard", "WireGuard"},
    {"openvpn-udp", "OpenVPN (UDP)"},
    {"openvpn-tcp", "OpenVPN (TCP)"},
};

}  // namespace


SettingsWindow::SettingsWindow(BWindow* parent)
    :
    BWindow(BRect(0, 0, 600, 500), "Settings", B_TITLED_WINDOW,
        B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE | B_NOT_ZOOMABLE)
{
    pvpn::Client& client = ProtonApp::Get()->Client();
    fFree = client.UserTier() == kTierFree;
    fRescope = client.ServerSelectionRequiresUpgrade();
    float spacing = be_control_look->DefaultItemSpacing();

    // Account
    fAccountName = new BStringView("account", client.AccountName().c_str());
    fAccountName->SetFont(be_bold_font);
    fPlan = new DescriptionView("plan", "");
    BButton* manage = new BButton("manage", "Manage Account", new BMessage(kMsgManageAccount));
    fRefresh = new BButton("refresh", "Refresh", new BMessage(kMsgRefreshAccount));
    fRefresh->SetToolTip("Refresh account details");
    BView* account = Section("Account");
    BLayoutBuilder::Group<>(static_cast<BGroupLayout*>(account->GetLayout()))
        .AddGroup(B_HORIZONTAL, spacing)
            .AddGroup(B_VERTICAL, 0)
                .Add(fAccountName)
                .Add(fPlan)
            .End()
            .AddGlue()
            .Add(manage)
            .Add(fRefresh)
        .End();

    // Features
    BPopUpMenu* netShieldMenu = new BPopUpMenu("netshield");
    for (int i = 0; i < 3; i++) {
        BMessage* message = new BMessage(kMsgNetShield);
        message->AddInt32("level", i);
        netShieldMenu->AddItem(new BMenuItem(kNetShieldLabels[i], message));
    }
    fNetShield = new BMenuField("netshield", nullptr, netShieldMenu);
    fKillSwitch = new BCheckBox("killswitch", "", new BMessage(kMsgKillSwitch));
    fKillStandard = new BRadioButton("standard", "Standard", new BMessage(kMsgKillMode));
    fKillAdvanced = new BRadioButton("advanced", "Advanced", new BMessage(kMsgKillMode));
    fKillModes = new BView("kill modes", 0);
    BLayoutBuilder::Group<>(fKillModes, B_VERTICAL, spacing / 2)
        .SetInsets(spacing * 2, 0, 0, 0)
        .Add(fKillStandard)
        .Add(new DescriptionView("standard description",
            "Automatically disconnect from the internet if VPN connection is lost."))
        .Add(fKillAdvanced)
        .Add(new DescriptionView("advanced description",
            "Only allow internet access when connected to Proton VPN. Advanced kill switch will "
            "remain active even when you restart Proton VPN."));
    fPortForwarding = new BCheckBox("port forwarding", "", new BMessage(kMsgPortForwarding));

    BView* features = Section("Features");
    BLayoutBuilder::Group<>(static_cast<BGroupLayout*>(features->GetLayout()))
        .Add(Row("NetShield", fNetShield,
            "Protect yourself from ads, malware, and trackers on websites and apps.", true))
        .Add(Row("Kill switch", fKillSwitch,
            "Protects your IP address by disconnecting you from the internet if you lose your VPN "
            "connection.\n\nKill switch can only be changed when VPN is disconnected.", false,
            new LinkView("ks learn more", "Learn more", "https://protonvpn.com/support/what-is-kill-switch/")))
        .Add(fKillModes)
        .Add(Row("Port forwarding", fPortForwarding,
            "Bypass firewalls to connect to P2P servers and devices on your local network.", true,
            new LinkView("pf learn more", "Learn more", "https://protonvpn.com/support/port-forwarding/")));

    // Connection
    BPopUpMenu* protocolMenu = new BPopUpMenu("protocol");
    for (const ProtocolChoice& choice : kProtocols) {
        BMessage* message = new BMessage(kMsgProtocol);
        message->AddString("protocol", choice.key);
        protocolMenu->AddItem(new BMenuItem(choice.title, message));
    }
    fProtocol = new BMenuField("protocol", nullptr, protocolMenu);
    fAccelerator = new BCheckBox("accelerator", "", new BMessage(kMsgAccelerator));
    fModerateNat = new BCheckBox("moderate nat", "", new BMessage(kMsgModerateNat));
    fIpv6 = new BCheckBox("ipv6", "", new BMessage(kMsgIpv6));
    fCustomDns = new BCheckBox("custom dns", "", new BMessage(kMsgCustomDns));
    fDnsList = new BListView("dns list");
    fDnsEntry = new BTextControl("dns entry", nullptr, "", new BMessage(kMsgAddDns));
    fDnsError = new BStringView("dns error", "");
    BScrollView* dnsScroll = new BScrollView("dns scroll", fDnsList, 0, false, true);
    dnsScroll->SetExplicitMinSize(BSize(B_SIZE_UNSET, be_plain_font->Size() * 6));
    fDnsPanel = new BView("dns panel", 0);
    BLayoutBuilder::Group<>(fDnsPanel, B_VERTICAL, spacing / 2)
        .SetInsets(spacing * 2, 0, 0, 0)
        .Add(new BStringView("add label", "Add new server"))
        .AddGroup(B_HORIZONTAL, spacing)
            .Add(fDnsEntry)
            .Add(new BButton("add", "Add", new BMessage(kMsgAddDns)))
        .End()
        .Add(fDnsError)
        .Add(dnsScroll)
        .AddGroup(B_HORIZONTAL)
            .AddGlue()
            .Add(new BButton("remove", "Remove", new BMessage(kMsgRemoveDns)))
        .End();

    BView* connection = Section("Connection");
    BLayoutBuilder::Group<>(static_cast<BGroupLayout*>(connection->GetLayout()))
        .Add(Row("Protocol", fProtocol,
            "Protocol can only be changed when VPN is disconnected.", false))
        .Add(Row("VPN Accelerator", fAccelerator,
            "Increase your connection speed by up to 400% with performance enhancing "
            "technologies.", true))
        .Add(Row("Moderate NAT", fModerateNat,
            "Disables randomization of the local addresses mapping. This can slightly reduce "
            "connection security, but should allow direct connections for online gaming and "
            "similar purposes.", true))
        .Add(Row("IPv6", fIpv6,
            "Tunnels IPv6 traffic through the VPN. Can enhance compatibility with IPv6 networks.",
            false))
        .Add(Row("Custom DNS servers", fCustomDns,
            "Connect to Proton VPN using your own domain name servers (DNS).", true))
        .Add(fDnsPanel);

    // General
    fAutoConnect = new BTextControl("auto connect", nullptr, "", new BMessage(kMsgAutoConnect));
    fAutoConnect->SetModificationMessage(new BMessage(kMsgAutoConnect));
    fStartMinimized = new BCheckBox("start minimized", "", new BMessage(kMsgStartMinimized));
    fTrayPins = new BTextControl("tray pins", nullptr, "", new BMessage(kMsgTrayPins));
    fTrayPins->SetModificationMessage(new BMessage(kMsgTrayPins));
    fCrashReports = new BCheckBox("crash reports", "", new BMessage(kMsgCrashReports));
    BView* general = Section("General");
    BLayoutBuilder::Group<>(static_cast<BGroupLayout*>(general->GetLayout()))
        .Add(Row("Auto connect", fAutoConnect,
            "You will be connected to a server as soon as Proton VPN app starts. Replace it with a "
            "country ISO code (e.g.: US for United States), a server (e.g.: NL#42) or Fastest for "
            "quick connection. Default value: Off.", fRescope))
        .Add(Row("Start app minimized", fStartMinimized,
            "When enabled, the app starts minimized to the tray.", false))
        .Add(Row("Pinned tray connections", fTrayPins,
            "Access preferred connections from system tray. Enter country or server codes, "
            "separated by commas, to quickly connect (e.g.: NL#42, JP, US, IT#01).", fRescope))
        .Add(Row("Share anonymous crash reports", fCrashReports,
            "Crash reports help us fix bugs, detect firewalls, and avoid VPN blocks.\n\nThese "
            "statistics do not contain your IP address, and they cannot be used to identify you. "
            "We'll never share them with third parties.", false));
    fAutoConnect->SetExplicitMinSize(BSize(be_plain_font->Size() * 10, B_SIZE_UNSET));
    fTrayPins->SetExplicitMinSize(BSize(be_plain_font->Size() * 10, B_SIZE_UNSET));

    BView* content = new BView("content", 0);
    BLayoutBuilder::Group<>(content, B_VERTICAL, spacing * 2)
        .SetInsets(spacing * 2)
        .Add(account)
        .Add(new BSeparatorView(B_HORIZONTAL))
        .Add(features)
        .Add(new BSeparatorView(B_HORIZONTAL))
        .Add(connection)
        .Add(new BSeparatorView(B_HORIZONTAL))
        .Add(general)
        .AddGlue();
    BScrollView* scroll = new BScrollView("scroll", content, 0, false, true, B_NO_BORDER);
    fNotification = new NotificationBar();
    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(fNotification)
        .Add(scroll);
    fNotification->Hide();

    float scale = be_plain_font->Size() / 12.0f;
    ResizeTo(600 * scale, 520 * scale);
    if (parent != nullptr)
        CenterIn(parent->Frame());
    Load();
}


BView* SettingsWindow::Section(const char* title)
{
    BView* section = new BView(title, 0);
    BStringView* heading = new BStringView("heading", title);
    BFont font(be_bold_font);
    font.SetSize(be_bold_font->Size() * 1.2f);
    heading->SetFont(&font);
    BGroupLayout* layout = new BGroupLayout(B_VERTICAL, be_control_look->DefaultItemSpacing());
    section->SetLayout(layout);
    // The heading goes in front of the rows the caller appends.
    layout->AddView(heading);
    return section;
}


BView* SettingsWindow::Row(const char* name, BView* control, const char* description,
    bool paidOnly, BView* extra, DescriptionView** descriptionOut)
{
    float spacing = be_control_look->DefaultItemSpacing();
    BView* row = new BView(name, 0);
    BStringView* label = new BStringView("name", name);
    label->SetFont(be_bold_font);
    BView* right = control;
    if (paidOnly && fFree) {
        BButton* upgrade = new BButton("upgrade", "VPN Plus", new BMessage(kMsgUpgrade));
        StyleButton(upgrade, AccentColor());
        right = upgrade;
        control->Hide();
    }
    DescriptionView* text = new DescriptionView("description", description);
    if (descriptionOut != nullptr)
        *descriptionOut = text;
    BGroupLayout* layout = BLayoutBuilder::Group<>(row, B_VERTICAL, spacing / 2)
        .AddGroup(B_HORIZONTAL, spacing)
            .Add(label)
            .AddGlue()
            .Add(right)
        .End()
        .Add(text);
    if (paidOnly && fFree)
        layout->AddView(control);
    if (extra != nullptr)
        layout->AddView(extra);
    return row;
}


bool SettingsWindow::QuitRequested()
{
    ProtonApp::Get()->SettingsWindowClosed();
    return true;
}


void SettingsWindow::Load()
{
    pvpn::Client& client = ProtonApp::Get()->Client();
    fSettings = client.GetSettings();
    BString plan;
    plan << "VPN plan: " << client.PlanTitle().c_str();
    fPlan->SetDescription(plan.String());
    if (BMenuItem* item = fNetShield->Menu()->ItemAt(std::max(0, std::min(fSettings.features.netshield, 2))))
        item->SetMarked(true);
    for (int i = 0; i < 3; i++) {
        if (fSettings.protocol == kProtocols[i].key)
            fProtocol->Menu()->ItemAt(i)->SetMarked(true);
    }
    fKillSwitch->SetValue(fSettings.killSwitch != kKillSwitchOff);
    fKillStandard->SetValue(fSettings.killSwitch != kKillSwitchAdvanced);
    fKillAdvanced->SetValue(fSettings.killSwitch == kKillSwitchAdvanced);
    fPortForwarding->SetValue(fSettings.features.portForwarding);
    fAccelerator->SetValue(fSettings.features.vpnAccelerator);
    fModerateNat->SetValue(fSettings.features.moderateNat);
    fIpv6->SetValue(fSettings.ipv6);
    fCustomDns->SetValue(fSettings.customDnsEnabled);
    while (BListItem* item = fDnsList->RemoveItem((int32)0))
        delete item;
    for (const std::string& ip : fSettings.customDns)
        fDnsList->AddItem(new BStringItem(ip.c_str()));
    AppConfig config = client.GetAppConfig();
    fAutoConnect->SetText(config.connectAtStartup.empty() ? "Off" : config.connectAtStartup.c_str());
    fStartMinimized->SetValue(config.startMinimized);
    fTrayPins->SetText(Join(config.trayPinnedServers, ", ").c_str());
    fCrashReports->SetValue(fSettings.anonymousCrashReports);
    UpdateState();
}


void SettingsWindow::UpdateState()
{
    VpnStatus status = ProtonApp::Get()->Status();
    bool disconnected = status.state == VpnState::Disconnected && !status.reconnecting;
    fKillSwitch->SetEnabled(disconnected);
    fKillStandard->SetEnabled(disconnected);
    fKillAdvanced->SetEnabled(disconnected);
    fProtocol->SetEnabled(disconnected);
    bool showModes = fKillSwitch->Value() == B_CONTROL_ON;
    SetVisible(fKillModes, showModes);
    bool showDns = fCustomDns->Value() == B_CONTROL_ON && !fFree;
    SetVisible(fDnsPanel, showDns);
}


void SettingsWindow::Notify(const char* text)
{
    fNotification->Show(text, kNotificationInfo);
}


void SettingsWindow::Save(const Settings& settings)
{
    fSettings = settings;
    ProtonApp::Get()->Client().SetSettings(settings);
    be_app->PostMessage(kMsgSettingsChanged);
}


void SettingsWindow::ApplyNetShield(int level)
{
    Settings settings = fSettings;
    settings.features.netshield = level;
    if (level != kNetShieldOff && settings.customDnsEnabled) {
        settings.customDnsEnabled = false;
        fCustomDns->SetValue(B_CONTROL_OFF);
    }
    Save(settings);
    UpdateState();
}


void SettingsWindow::ApplyCustomDns(bool enabled)
{
    Settings settings = fSettings;
    settings.customDnsEnabled = enabled;
    VpnStatus status = ProtonApp::Get()->Status();
    bool connected = status.state == VpnState::Connected;
    if (enabled && settings.features.netshield != kNetShieldOff) {
        settings.features.netshield = kNetShieldOff;
        fNetShield->Menu()->ItemAt(0)->SetMarked(true);
        // WireGuard applies the feature change live; OpenVPN needs a reconnection.
        if (connected && status.server.protocol != kProtocolWireGuard)
            Notify(kReconnectText);
    }
    if (connected && !settings.customDns.empty())
        Notify(kReconnectText);
    Save(settings);
    UpdateState();
}


void SettingsWindow::MessageReceived(BMessage* message)
{
    pvpn::Client& client = ProtonApp::Get()->Client();
    switch (message->what) {
        case kMsgNetShield: {
            int level = message->GetInt32("level", 0);
            if (level != kNetShieldOff && fSettings.customDnsEnabled) {
                BAlert* alert = new BAlert("Enable Netshield",
                    "Enable Netshield?\n\nThis will disable custom DNS.", "Cancel", "Enable");
                BMessage* reply = new BMessage(kMsgNetShieldConfirmed);
                reply->AddInt32("level", level);
                alert->Go(new BInvoker(reply, this));
                break;
            }
            ApplyNetShield(level);
            break;
        }
        case kMsgNetShieldConfirmed:
            if (message->GetInt32("which", 0) == 1) {
                ApplyNetShield(message->GetInt32("level", 0));
            } else if (BMenuItem* item = fNetShield->Menu()->ItemAt(0)) {
                item->SetMarked(true);
                Settings settings = fSettings;
                settings.features.netshield = kNetShieldOff;
                Save(settings);
            }
            break;
        case kMsgKillSwitch: {
            Settings settings = fSettings;
            if (fKillSwitch->Value() == B_CONTROL_ON) {
                settings.killSwitch = kKillSwitchStandard;
                fKillStandard->SetValue(B_CONTROL_ON);
            } else {
                settings.killSwitch = kKillSwitchOff;
            }
            Save(settings);
            UpdateState();
            break;
        }
        case kMsgKillMode: {
            Settings settings = fSettings;
            settings.killSwitch = fKillAdvanced->Value() == B_CONTROL_ON
                ? kKillSwitchAdvanced : kKillSwitchStandard;
            Save(settings);
            break;
        }
        case kMsgPortForwarding: {
            Settings settings = fSettings;
            settings.features.portForwarding = fPortForwarding->Value() == B_CONTROL_ON;
            Save(settings);
            break;
        }
        case kMsgProtocol: {
            Settings settings = fSettings;
            settings.protocol = message->GetString("protocol", kProtocolWireGuard);
            Save(settings);
            break;
        }
        case kMsgAccelerator: {
            Settings settings = fSettings;
            settings.features.vpnAccelerator = fAccelerator->Value() == B_CONTROL_ON;
            Save(settings);
            break;
        }
        case kMsgModerateNat: {
            Settings settings = fSettings;
            settings.features.moderateNat = fModerateNat->Value() == B_CONTROL_ON;
            Save(settings);
            break;
        }
        case kMsgIpv6: {
            Settings settings = fSettings;
            settings.ipv6 = fIpv6->Value() == B_CONTROL_ON;
            Save(settings);
            Notify(kReconnectText);
            break;
        }
        case kMsgCustomDns: {
            bool enabled = fCustomDns->Value() == B_CONTROL_ON;
            if (enabled && fSettings.features.netshield != kNetShieldOff) {
                BAlert* alert = new BAlert("Enable Custom DNS",
                    "Enable Custom DNS?\n\nThis will disable NetShield.", "Cancel", "Enable");
                alert->Go(new BInvoker(new BMessage(kMsgCustomDnsConfirmed), this));
                break;
            }
            ApplyCustomDns(enabled);
            break;
        }
        case kMsgCustomDnsConfirmed:
            if (message->GetInt32("which", 0) == 1)
                ApplyCustomDns(true);
            else
                fCustomDns->SetValue(B_CONTROL_OFF);
            break;
        case kMsgAddDns: {
            std::string ip = Trim(fDnsEntry->Text());
            if (!IsValidIpAddress(ip)) {
                fDnsError->SetText("Enter a valid IPv4 or IPv6 address");
                fDnsError->SetHighColor(DangerColor());
                break;
            }
            fDnsError->SetText("");
            Settings settings = fSettings;
            if (std::find(settings.customDns.begin(), settings.customDns.end(), ip)
                == settings.customDns.end()) {
                settings.customDns.push_back(ip);
                fDnsList->AddItem(new BStringItem(ip.c_str()));
            }
            fDnsEntry->SetText("");
            Save(settings);
            if (ProtonApp::Get()->Status().state == VpnState::Connected)
                Notify(kReconnectText);
            break;
        }
        case kMsgRemoveDns: {
            int32 index = fDnsList->CurrentSelection();
            if (index < 0)
                break;
            Settings settings = fSettings;
            if (index < (int32)settings.customDns.size())
                settings.customDns.erase(settings.customDns.begin() + index);
            delete fDnsList->RemoveItem(index);
            Save(settings);
            if (ProtonApp::Get()->Status().state == VpnState::Connected)
                Notify(kReconnectText);
            break;
        }
        case kMsgAutoConnect: {
            AppConfig config = client.GetAppConfig();
            std::string value = ToUpper(Trim(fAutoConnect->Text()));
            config.connectAtStartup = value == "OFF" ? "" : value;
            client.SetAppConfig(config);
            break;
        }
        case kMsgStartMinimized: {
            AppConfig config = client.GetAppConfig();
            config.startMinimized = fStartMinimized->Value() == B_CONTROL_ON;
            client.SetAppConfig(config);
            break;
        }
        case kMsgTrayPins: {
            AppConfig config = client.GetAppConfig();
            config.trayPinnedServers.clear();
            for (const std::string& pin : Split(fTrayPins->Text(), ',')) {
                std::string value = ToUpper(Trim(pin));
                if (!value.empty())
                    config.trayPinnedServers.push_back(value);
            }
            client.SetAppConfig(config);
            break;
        }
        case kMsgCrashReports: {
            Settings settings = fSettings;
            settings.anonymousCrashReports = fCrashReports->Value() == B_CONTROL_ON;
            Save(settings);
            break;
        }
        case kMsgUpgrade:
            OpenUrl(kPricingUrl);
            break;
        case kMsgManageAccount:
            OpenUrl("https://account.protonvpn.com/account");
            break;
        case kMsgRefreshAccount: {
            fRefresh->SetEnabled(false);
            BMessenger target(this);
            std::thread([target]() {
                BMessage reply(kMsgAccountRefreshed);
                reply.AddBool("ok", ProtonApp::Get()->Client().RefreshAccountInfo().Ok());
                target.SendMessage(&reply);
            }).detach();
            break;
        }
        case kMsgAccountRefreshed:
            fRefresh->SetEnabled(true);
            if (message->GetBool("ok", false)) {
                Notify("Account info refreshed, restart the app to see changes");
                Load();
            } else {
                fNotification->Show("Account info refresh failed, check your connection and try "
                    "again", kNotificationError);
            }
            break;
        case kMsgAccountChanged: {
            BString plan;
            plan << "VPN plan: " << client.PlanTitle().c_str();
            fPlan->SetDescription(plan.String());
            break;
        }
        case kMsgVpnStatus:
            UpdateState();
            break;
        default:
            BWindow::MessageReceived(message);
    }
}
