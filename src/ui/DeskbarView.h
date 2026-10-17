// The Deskbar tray icon (the GTK app's tray indicator). Deskbar loads it from
// the Proton VPN executable as an add-on; it asks the app for its state every
// two seconds and offers Connect/Disconnect, the pinned connections,
// Show/Hide and Quit.
#pragma once
#include <View.h>
#include <string>
#include <vector>

class BBitmap;
class BMessageRunner;

class ProtonDeskbarView : public BView {
public:
    explicit ProtonDeskbarView(BRect frame);
    explicit ProtonDeskbarView(BMessage* archive);
    ~ProtonDeskbarView() override;

    static BArchivable* Instantiate(BMessage* archive);
    status_t Archive(BMessage* archive, bool deep = true) const override;

    void AttachedToWindow() override;
    void DetachedFromWindow() override;
    void Draw(BRect updateRect) override;
    void MouseDown(BPoint where) override;
    void MessageReceived(BMessage* message) override;

    static const char* kName;

private:
    void Init();
    void Poll();
    void ShowMenu(BPoint where);

    BBitmap* fConnected = nullptr;
    BBitmap* fDisconnected = nullptr;
    BBitmap* fError = nullptr;
    BMessageRunner* fPoller = nullptr;
    bool fAppRunning = false;
    int32 fState = 0;
    bool fReconnecting = false;
    bool fLoggedIn = false;
    bool fVisible = false;
    std::vector<std::string> fPins;
};
