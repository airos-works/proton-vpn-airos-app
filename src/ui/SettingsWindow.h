// Settings: Account, Features, Connection and General, as the GTK app's
// settings window. Changes are saved at once; features (NetShield, VPN
// Accelerator, moderate NAT, port forwarding) reach a running connection
// through the local agent, the rest applies to the next connection.
#pragma once
#include "core/Settings.h"
#include <Window.h>

class BButton;
class BCheckBox;
class BListView;
class BMenuField;
class BRadioButton;
class BStringView;
class BTextControl;
class DescriptionView;
class NotificationBar;

class SettingsWindow : public BWindow {
public:
    explicit SettingsWindow(BWindow* parent);

    bool QuitRequested() override;
    void MessageReceived(BMessage* message) override;

private:
    BView* Section(const char* title);
    BView* Row(const char* name, BView* control, const char* description, bool paidOnly,
        BView* extra = nullptr, DescriptionView** descriptionOut = nullptr);
    void Load();
    void Save(const pvpn::Settings& settings);
    void UpdateState();
    void Notify(const char* text);
    void ApplyNetShield(int level);
    void ApplyCustomDns(bool enabled);

    bool fFree = false;
    bool fRescope = false;
    pvpn::Settings fSettings;
    NotificationBar* fNotification;
    BStringView* fAccountName;
    DescriptionView* fPlan;
    BButton* fRefresh;
    BMenuField* fNetShield;
    BCheckBox* fKillSwitch;
    BRadioButton* fKillStandard;
    BRadioButton* fKillAdvanced;
    BView* fKillModes;
    BCheckBox* fPortForwarding;
    BMenuField* fProtocol;
    BCheckBox* fAccelerator;
    BCheckBox* fModerateNat;
    BCheckBox* fIpv6;
    BCheckBox* fCustomDns;
    BView* fDnsPanel;
    BListView* fDnsList;
    BTextControl* fDnsEntry;
    BStringView* fDnsError;
    BTextControl* fAutoConnect;
    BCheckBox* fStartMinimized;
    BTextControl* fTrayPins;
    BCheckBox* fCrashReports;
};
