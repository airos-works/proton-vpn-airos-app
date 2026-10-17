// The connection status block at the top of the main window: "Unprotected",
// "Connecting...", "Protected", "Disconnecting..." or "Connection error" with
// the shield (or a spinner), the server it is about, and the forwarded port
// (click to copy). The background carries the GTK app's state tint.
#pragma once
#include "core/Connector.h"
#include <View.h>
#include <string>
#include <vector>

class BMessageRunner;

class StatusView : public BView {
public:
    StatusView();
    ~StatusView() override;

    void SetStatus(const pvpn::VpnStatus& status, int userTier, bool rescope,
        const std::vector<std::string>& freeCountries);

    void AttachedToWindow() override;
    void DetachedFromWindow() override;
    void Draw(BRect updateRect) override;
    void MouseDown(BPoint where) override;
    void MessageReceived(BMessage* message) override;
    BSize MinSize() override;
    BSize PreferredSize() override;
    BSize MaxSize() override;

private:
    float RowHeight(const BFont& font) const;
    void UpdateSpinner();

    pvpn::VpnStatus fStatus;
    int fTier = 0;
    bool fRescope = false;
    std::vector<std::string> fFreeCountries;
    BRect fPortRect;
    BRect fFreeRect;            // the free countries summary (click: details)
    bool fCopied = false;
    int fPhase = 0;
    BMessageRunner* fSpinner = nullptr;
    BMessageRunner* fCopiedTimer = nullptr;
};

// The title and detail texts the GTK app shows for a status.
const char* StatusTitle(const pvpn::VpnStatus& status);
const char* StatusErrorDetail(const pvpn::VpnStatus& status);
