#include "Widgets.h"
#include "Icons.h"
#include "Messages.h"
#include <Bitmap.h>
#include <Button.h>
#include <ControlLook.h>
#include <GroupLayout.h>
#include <MessageRunner.h>
#include <Url.h>
#include <Window.h>
#include <cmath>

namespace {

const uint32 kMsgDismiss = 'dism';

bool DarkPanel()
{
    return Icons::Brightness(ui_color(B_PANEL_BACKGROUND_COLOR)) < 128;
}

}  // namespace


void SetVisible(BView* view, bool visible)
{
    bool hidden = view->IsHidden(view);
    if (visible && hidden)
        view->Show();
    else if (!visible && !hidden)
        view->Hide();
}


void OpenUrl(const char* url)
{
    BUrl target(url, true);
    if (target.IsValid())
        target.OpenWithPreferredApplication(false);
}


rgb_color AccentColor()
{
    // #6D4AFF on light panels, #8A6EFF on dark ones.
    return DarkPanel() ? make_color(0x8a, 0x6e, 0xff) : make_color(0x6d, 0x4a, 0xff);
}


rgb_color DangerColor()
{
    return DarkPanel() ? make_color(0xf7, 0x60, 0x7e) : make_color(0xdc, 0x32, 0x51);
}


rgb_color SuccessColor()
{
    return DarkPanel() ? make_color(0x4b, 0xb9, 0x9d) : make_color(0x1e, 0xa8, 0x85);
}


rgb_color WarningColor()
{
    return make_color(0xff, 0xad, 0x33);
}


rgb_color WeakTextColor()
{
    return Icons::Mix(ui_color(B_PANEL_TEXT_COLOR), ui_color(B_PANEL_BACKGROUND_COLOR), 0.35f);
}


void StyleButton(BButton* button, rgb_color base)
{
    // BButton draws its background from its low colour.
    button->SetLowColor(Icons::Mix(ui_color(B_CONTROL_BACKGROUND_COLOR), base, 0.55f));
    button->SetViewColor(button->LowColor());
    button->Invalidate();
}


LinkView::LinkView(const char* name, const char* label, const char* url)
    :
    BStringView(name, label),
    fUrl(url)
{
}


void LinkView::AttachedToWindow()
{
    BStringView::AttachedToWindow();
    SetHighColor(ui_color(B_LINK_TEXT_COLOR));
}


void LinkView::Draw(BRect updateRect)
{
    SetHighColor(fHover ? ui_color(B_LINK_HOVER_COLOR) : ui_color(B_LINK_TEXT_COLOR));
    BStringView::Draw(updateRect);
    if (fHover) {
        font_height height;
        GetFontHeight(&height);
        float width = StringWidth(Text());
        float x = 0;
        if (Alignment() == B_ALIGN_RIGHT)
            x = Bounds().right - width;
        else if (Alignment() == B_ALIGN_CENTER)
            x = (Bounds().Width() - width) / 2;
        float y = floorf((Bounds().Height() + height.ascent - height.descent) / 2) + 2;
        StrokeLine(BPoint(x, y), BPoint(x + width, y));
    }
}


void LinkView::MouseDown(BPoint where)
{
    if (!fUrl.empty())
        OpenUrl(fUrl.c_str());
}


void LinkView::MouseMoved(BPoint where, uint32 transit, const BMessage* message)
{
    bool hover = transit == B_ENTERED_VIEW || transit == B_INSIDE_VIEW;
    if (hover != fHover) {
        fHover = hover;
        Invalidate();
    }
}


DescriptionView::DescriptionView(const char* name, const char* text, bool weak)
    :
    BTextView(name),
    fWeak(weak)
{
    MakeEditable(false);
    MakeSelectable(false);
    SetWordWrap(true);
    SetStylable(false);
    SetText(text);
    SetInsets(0, 0, 0, 0);
}


void DescriptionView::AttachedToWindow()
{
    BTextView::AttachedToWindow();
    SetViewUIColor(B_PANEL_BACKGROUND_COLOR);
    SetLowUIColor(B_PANEL_BACKGROUND_COLOR);
    rgb_color color = fWeak ? WeakTextColor() : ui_color(B_PANEL_TEXT_COLOR);
    SetFontAndColor(be_plain_font, B_FONT_ALL, &color);
}


void DescriptionView::SetDescription(const char* text)
{
    SetText(text);
    rgb_color color = fWeak ? WeakTextColor() : ui_color(B_PANEL_TEXT_COLOR);
    SetFontAndColor(be_plain_font, B_FONT_ALL, &color);
    InvalidateLayout();
}


void DescriptionView::FrameResized(float width, float height)
{
    BTextView::FrameResized(width, height);
    InvalidateLayout();
}


BSize DescriptionView::MinSize()
{
    return BSize(be_plain_font->Size() * 12, BTextView::MinSize().height);
}


NotificationBar::NotificationBar()
    :
    BView("notification bar", B_WILL_DRAW)
{
    fText = new DescriptionView("text", "", false);
    BGroupLayout* layout = new BGroupLayout(B_VERTICAL);
    SetLayout(layout);
    float inset = be_control_look->DefaultItemSpacing();
    layout->SetInsets(inset, inset / 2, inset, inset / 2);
    AddChild(fText);
}


void NotificationBar::Show(const char* text, NotificationKind kind, bigtime_t duration)
{
    fKind = kind;
    rgb_color base = kind == kNotificationError ? DangerColor()
        : kind == kNotificationSuccess ? SuccessColor() : AccentColor();
    rgb_color background = Icons::Mix(ui_color(B_PANEL_BACKGROUND_COLOR), base, 0.25f);
    SetViewColor(background);
    fText->SetViewColor(background);
    fText->SetLowColor(background);
    fText->SetText(text);
    rgb_color color = ui_color(B_PANEL_TEXT_COLOR);
    fText->SetFontAndColor(be_plain_font, B_FONT_ALL, &color);
    fText->SetAlignment(B_ALIGN_CENTER);
    delete fTimer;
    BMessage dismiss(kMsgDismiss);
    fTimer = new BMessageRunner(BMessenger(this), &dismiss, duration, 1);
    SetVisible(this, true);
    Invalidate();
    fText->Invalidate();
}


void NotificationBar::Dismiss()
{
    delete fTimer;
    fTimer = nullptr;
    SetVisible(this, false);
}


const char* NotificationBar::Text() const
{
    return IsHidden(this) ? "" : fText->Text();
}


void NotificationBar::MessageReceived(BMessage* message)
{
    if (message->what == kMsgDismiss) {
        Dismiss();
        return;
    }
    BView::MessageReceived(message);
}


void NotificationBar::Draw(BRect updateRect)
{
    rgb_color base = fKind == kNotificationError ? DangerColor()
        : fKind == kNotificationSuccess ? SuccessColor() : AccentColor();
    SetHighColor(base);
    BRect bounds = Bounds();
    FillRect(BRect(bounds.left, bounds.top, bounds.left + 3, bounds.bottom));
}


void NotificationBar::MouseDown(BPoint where)
{
    Dismiss();
}


Spinner::Spinner(float size)
    :
    BView("spinner", B_WILL_DRAW),
    fSize(size)
{
    SetExplicitSize(BSize(size, size));
}


Spinner::~Spinner()
{
    delete fRunner;
}


void Spinner::Start()
{
    fWanted = true;
    if (fRunner == nullptr && Window() != nullptr) {
        BMessage pulse(kMsgSpinner);
        fRunner = new BMessageRunner(BMessenger(this), &pulse, 80000);
    }
    Invalidate();
}


void Spinner::Stop()
{
    fWanted = false;
    delete fRunner;
    fRunner = nullptr;
    Invalidate();
}


void Spinner::AttachedToWindow()
{
    BView::AttachedToWindow();
    AdoptParentColors();
    if (fWanted)
        Start();
}


void Spinner::DetachedFromWindow()
{
    delete fRunner;
    fRunner = nullptr;
    BView::DetachedFromWindow();
}


void Spinner::MessageReceived(BMessage* message)
{
    if (message->what == kMsgSpinner) {
        fPhase = (fPhase + 1) % 12;
        Invalidate();
        return;
    }
    BView::MessageReceived(message);
}


void Spinner::Draw(BRect updateRect)
{
    if (!fWanted)
        return;
    SetDrawingMode(B_OP_ALPHA);
    SetBlendingMode(B_CONSTANT_ALPHA, B_ALPHA_OVERLAY);
    BRect bounds = Bounds();
    BPoint center((bounds.left + bounds.right) / 2, (bounds.top + bounds.bottom) / 2);
    float outer = std::min(bounds.Width(), bounds.Height()) / 2 - 1;
    float inner = outer * 0.45f;
    SetPenSize(std::max(1.5f, outer / 5));
    SetLineMode(B_ROUND_CAP, B_ROUND_JOIN);
    rgb_color color = AccentColor();
    for (int i = 0; i < 12; i++) {
        int age = (fPhase - i + 12) % 12;
        color.alpha = (uint8)(255 - age * 18);
        SetHighColor(color);
        float angle = i * M_PI / 6;
        StrokeLine(BPoint(center.x + inner * sinf(angle), center.y - inner * cosf(angle)),
            BPoint(center.x + outer * sinf(angle), center.y - outer * cosf(angle)));
    }
    SetPenSize(1);
    SetDrawingMode(B_OP_COPY);
}


PictureView::PictureView(const char* name, const char* icon, float width)
    :
    BView(name, B_WILL_DRAW),
    fIcon(icon),
    fWidth(width)
{
}


const BBitmap* PictureView::Bitmap() const
{
    // The wordmark is white for dark panels; "logo-dark" has dark text.
    if (fIcon == "logo" && Icons::Brightness(ui_color(B_PANEL_BACKGROUND_COLOR)) >= 128) {
        if (const BBitmap* dark = Icons::Get("logo-dark"))
            return dark;
    }
    return Icons::Get(fIcon.c_str());
}


void PictureView::AttachedToWindow()
{
    BView::AttachedToWindow();
    AdoptParentColors();
}


void PictureView::Draw(BRect updateRect)
{
    const BBitmap* bitmap = Bitmap();
    if (bitmap == nullptr)
        return;
    BRect source = bitmap->Bounds();
    float height = fWidth * (source.Height() + 1) / (source.Width() + 1);
    BRect bounds = Bounds();
    BRect dest(0, 0, fWidth - 1, height - 1);
    dest.OffsetTo(floorf((bounds.Width() - fWidth) / 2), floorf((bounds.Height() - height) / 2));
    Icons::Draw(this, bitmap, dest);
}


BSize PictureView::MinSize()
{
    const BBitmap* bitmap = Bitmap();
    float height = bitmap == nullptr ? 0
        : fWidth * (bitmap->Bounds().Height() + 1) / (bitmap->Bounds().Width() + 1);
    return BSize(fWidth, height);
}


BSize PictureView::MaxSize()
{
    BSize size = MinSize();
    return BSize(B_SIZE_UNLIMITED, size.height);
}


BSize PictureView::PreferredSize()
{
    return MinSize();
}
