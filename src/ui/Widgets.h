// Small native widgets the windows share: link labels, wrapped description
// text, the notification bar (the GTK app's slide-in message strip), a spinner
// and a picture view.
#pragma once
#include <StringView.h>
#include <TextView.h>
#include <View.h>
#include <string>

class BBitmap;
class BMessageRunner;

// Opens a URL with the preferred application (WebPositive or Summit).
void OpenUrl(const char* url);

// Proton's accent colours, adapted to the panel colour.
rgb_color AccentColor();
rgb_color DangerColor();
rgb_color SuccessColor();
rgb_color WarningColor();
rgb_color WeakTextColor();
// A button in the accent (primary) or danger colour.
void StyleButton(class BButton* button, rgb_color base);

class LinkView : public BStringView {
public:
    LinkView(const char* name, const char* label, const char* url);

    void SetUrl(const char* url) { fUrl = url; }
    void AttachedToWindow() override;
    void Draw(BRect updateRect) override;
    void MouseDown(BPoint where) override;
    void MouseMoved(BPoint where, uint32 transit, const BMessage* message) override;

private:
    std::string fUrl;
    bool fHover = false;
};

// Non-editable wrapping text in the weak text colour.
class DescriptionView : public BTextView {
public:
    DescriptionView(const char* name, const char* text, bool weak = true);

    void AttachedToWindow() override;
    void SetDescription(const char* text);
    void FrameResized(float width, float height) override;
    BSize MinSize() override;

private:
    bool fWeak;
};

enum NotificationKind {
    kNotificationError,
    kNotificationInfo,
    kNotificationSuccess,
};

class NotificationBar : public BView {
public:
    NotificationBar();

    void Show(const char* text, NotificationKind kind, bigtime_t duration = 10000000);
    void Dismiss();
    const char* Text() const;
    void MessageReceived(BMessage* message) override;
    void Draw(BRect updateRect) override;
    void MouseDown(BPoint where) override;

private:
    BTextView* fText;
    BMessageRunner* fTimer = nullptr;
    NotificationKind fKind = kNotificationInfo;
};

class Spinner : public BView {
public:
    explicit Spinner(float size);
    ~Spinner() override;

    void Start();
    void Stop();
    bool Running() const { return fRunner != nullptr; }
    void AttachedToWindow() override;
    void DetachedFromWindow() override;
    void Draw(BRect updateRect) override;
    void MessageReceived(BMessage* message) override;

private:
    float fSize;
    int fPhase = 0;
    bool fWanted = false;
    BMessageRunner* fRunner = nullptr;
};

// Draws a bitmap resource ("logo", "sign", ...) scaled to a width.
class PictureView : public BView {
public:
    PictureView(const char* name, const char* icon, float width);

    void AttachedToWindow() override;
    void Draw(BRect updateRect) override;
    BSize MinSize() override;
    BSize MaxSize() override;
    BSize PreferredSize() override;

private:
    const BBitmap* Bitmap() const;

    std::string fIcon;
    float fWidth;
};
