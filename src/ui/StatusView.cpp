#include "StatusView.h"
#include "Icons.h"
#include "Messages.h"
#include "Widgets.h"
#include "core/Countries.h"
#include <Clipboard.h>
#include <Font.h>
#include <GradientLinear.h>
#include <MessageRunner.h>
#include <Window.h>
#include <cmath>

using namespace pvpn;

namespace {

const uint32 kMsgCopiedDone = 'cpdn';

float Scaled(float value)
{
    return roundf(value * Icons::Scale());
}

bool Busy(const VpnStatus& status)
{
    return status.state == VpnState::Connecting || status.state == VpnState::Disconnecting
        || (status.state == VpnState::Disconnected && status.reconnecting);
}

}  // namespace


const char* StatusTitle(const VpnStatus& status)
{
    switch (status.state) {
        case VpnState::Connecting:
            return "Connecting...";
        case VpnState::Connected:
            return "Protected";
        case VpnState::Disconnecting:
            return status.reconnecting ? "Connecting..." : "Disconnecting...";
        case VpnState::Error:
            return "Connection error";
        case VpnState::Disconnected:
            return status.reconnecting ? "Connecting..." : "Unprotected";
    }
    return "";
}


const char* StatusErrorDetail(const VpnStatus& status)
{
    if (status.state != VpnState::Error)
        return "";
    switch (status.event) {
        case VpnEvent::TunnelSetupFailed:
            return "Tunnel setup failed";
        case VpnEvent::AuthDenied:
            return "Authentication denied";
        case VpnEvent::Timeout:
            return "Timeout";
        case VpnEvent::DeviceDisconnected:
            return "Device disconnected";
        case VpnEvent::MaximumSessionsReached:
            return "Session limit reached";
        default:
            return "";
    }
}


StatusView::StatusView()
    :
    BView("status", B_WILL_DRAW | B_FULL_UPDATE_ON_RESIZE)
{
}


StatusView::~StatusView()
{
    delete fSpinner;
    delete fCopiedTimer;
}


void StatusView::AttachedToWindow()
{
    BView::AttachedToWindow();
    SetViewColor(B_TRANSPARENT_COLOR);
    UpdateSpinner();
}


void StatusView::DetachedFromWindow()
{
    delete fSpinner;
    fSpinner = nullptr;
    BView::DetachedFromWindow();
}


void StatusView::SetStatus(const VpnStatus& status, int userTier, bool rescope,
    const std::vector<std::string>& freeCountries)
{
    bool resize = (status.forwardedPort != 0) != (fStatus.forwardedPort != 0)
        || (fStatus.state == VpnState::Error) != (status.state == VpnState::Error);
    fStatus = status;
    fTier = userTier;
    fRescope = rescope;
    fFreeCountries = freeCountries;
    UpdateSpinner();
    if (resize)
        InvalidateLayout();
    Invalidate();
}


void StatusView::UpdateSpinner()
{
    bool busy = Busy(fStatus);
    if (busy && fSpinner == nullptr && Window() != nullptr) {
        BMessage pulse(kMsgSpinner);
        fSpinner = new BMessageRunner(BMessenger(this), &pulse, 80000);
    } else if (!busy && fSpinner != nullptr) {
        delete fSpinner;
        fSpinner = nullptr;
    }
}


void StatusView::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgSpinner:
            fPhase = (fPhase + 1) % 12;
            Invalidate();
            break;
        case kMsgCopiedDone:
            fCopied = false;
            delete fCopiedTimer;
            fCopiedTimer = nullptr;
            Invalidate();
            break;
        default:
            BView::MessageReceived(message);
    }
}


float StatusView::RowHeight(const BFont& font) const
{
    font_height height;
    font.GetHeight(&height);
    return ceilf(height.ascent + height.descent + height.leading);
}


BSize StatusView::MinSize()
{
    BFont title(be_bold_font);
    title.SetSize(be_bold_font->Size() * 1.4f);
    float height = Scaled(12) + std::max(RowHeight(title), Scaled(24)) + Scaled(10);
    if (fStatus.state == VpnState::Error)
        height += RowHeight(*be_plain_font) + Scaled(2);
    height += std::max(RowHeight(*be_bold_font) + RowHeight(*be_plain_font), Scaled(24)) + Scaled(8);
    if (fStatus.state == VpnState::Connected && fStatus.forwardedPort != 0)
        height += RowHeight(*be_plain_font) + Scaled(10);
    return BSize(Scaled(260), height + Scaled(8));
}


BSize StatusView::PreferredSize()
{
    return MinSize();
}


BSize StatusView::MaxSize()
{
    return BSize(B_SIZE_UNLIMITED, MinSize().height);
}


void StatusView::Draw(BRect updateRect)
{
    BRect bounds = Bounds();
    rgb_color panel = ui_color(B_PANEL_BACKGROUND_COLOR);
    rgb_color text = ui_color(B_PANEL_TEXT_COLOR);
    // The state tint fades into the panel colour.
    rgb_color tint = panel;
    if (fStatus.state == VpnState::Connected)
        tint = Icons::Mix(panel, SuccessColor(), 0.2f);
    else if (fStatus.state == VpnState::Disconnected && !fStatus.reconnecting)
        tint = Icons::Mix(panel, DangerColor(), 0.2f);
    else
        tint = Icons::Mix(panel, text, 0.08f);
    BGradientLinear gradient(bounds.LeftTop(), bounds.LeftBottom());
    gradient.AddColor(tint, 0);
    gradient.AddColor(panel, 255);
    FillRect(bounds, gradient);
    SetLowColor(panel);

    // Title row: shield (or spinner) and the state.
    BFont title(be_bold_font);
    title.SetSize(be_bold_font->Size() * 1.4f);
    SetFont(&title);
    const char* label = StatusTitle(fStatus);
    float iconSize = Scaled(24);
    float titleWidth = StringWidth(label);
    float rowHeight = std::max(RowHeight(title), iconSize);
    float top = Scaled(12);
    float left = floorf((bounds.Width() - (iconSize + Scaled(8) + titleWidth)) / 2);
    BRect icon(left, top + (rowHeight - iconSize) / 2, left + iconSize - 1,
        top + (rowHeight - iconSize) / 2 + iconSize - 1);
    if (Busy(fStatus)) {
        BPoint center((icon.left + icon.right) / 2, (icon.top + icon.bottom) / 2);
        float outer = iconSize / 2 - 1, inner = outer * 0.45f;
        SetDrawingMode(B_OP_ALPHA);
        SetBlendingMode(B_CONSTANT_ALPHA, B_ALPHA_OVERLAY);
        SetPenSize(std::max(1.5f, outer / 5));
        SetLineMode(B_ROUND_CAP, B_ROUND_JOIN);
        rgb_color color = AccentColor();
        for (int i = 0; i < 12; i++) {
            color.alpha = (uint8)(255 - ((fPhase - i + 12) % 12) * 18);
            SetHighColor(color);
            float angle = i * M_PI / 6;
            StrokeLine(BPoint(center.x + inner * sinf(angle), center.y - inner * cosf(angle)),
                BPoint(center.x + outer * sinf(angle), center.y - outer * cosf(angle)));
        }
        SetPenSize(1);
        SetDrawingMode(B_OP_COPY);
    } else if (fStatus.state == VpnState::Connected) {
        Icons::Draw(this, Icons::Get("protected"), icon);
    } else if (fStatus.state == VpnState::Disconnected) {
        Icons::Draw(this, Icons::Get("unprotected"), icon);
    }
    font_height titleHeight;
    title.GetHeight(&titleHeight);
    float baseline = floorf(top + rowHeight / 2 + (titleHeight.ascent - titleHeight.descent) / 2);
    if (fStatus.state == VpnState::Connected)
        SetHighColor(SuccessColor());
    else if (fStatus.state == VpnState::Disconnected && !fStatus.reconnecting)
        SetHighColor(DangerColor());
    else
        SetHighColor(text);
    SetDrawingMode(B_OP_OVER);
    DrawString(label, BPoint(icon.right + Scaled(8) + 1, baseline));
    float y = top + rowHeight + Scaled(10);

    SetFont(be_plain_font);
    font_height plainHeight;
    be_plain_font->GetHeight(&plainHeight);
    float plainRow = RowHeight(*be_plain_font);
    const char* detail = StatusErrorDetail(fStatus);
    if (fStatus.state == VpnState::Error) {
        SetHighColor(WeakTextColor());
        float width = StringWidth(detail);
        DrawString(detail, BPoint(floorf((bounds.Width() - width) / 2), y + plainHeight.ascent));
        y += plainRow + Scaled(2);
    }

    // The server row.
    float margin = Scaled(14);
    BRect flag(margin, y + Scaled(4), margin + Scaled(36) - 1, y + Scaled(4) + Scaled(24) - 1);
    std::string heading, subtitle;
    bool showServer = fStatus.hasServer && (fStatus.state != VpnState::Disconnected
        || fStatus.reconnecting);
    if (showServer) {
        const LogicalServer& server = fStatus.server.logical;
        BRect flagRect(flag.left + Scaled(6), flag.top + Scaled(4), flag.left + Scaled(30) - 1,
            flag.top + Scaled(20) - 1);
        if (server.Has(kFeatureSecureCore)) {
            Icons::DrawDoubleFlag(this, server.exitCountry, server.entryCountry,
                BRect(flag.left, flag.top, flag.right, flag.bottom));
            subtitle = "Via " + CountryName(server.entryCountry);
        } else {
            Icons::DrawFlag(this, server.exitCountry, flagRect);
            std::string location = server.Location();
            subtitle = location.empty() ? server.name : location + " - " + server.name;
        }
        heading = CountryName(server.exitCountry);
    } else {
        Icons::Draw(this, Icons::Get("fastest"), BRect(flag.left, flag.top + Scaled(2), flag.right,
            flag.top + Scaled(26) - 1));
        if (fTier == kTierFree) {
            heading = "Fastest free server";
            subtitle = "Auto-selected from free locations";
        } else {
            heading = "Fastest country";
        }
    }
    float textLeft = flag.right + Scaled(10);
    SetFont(be_bold_font);
    font_height boldHeight;
    be_bold_font->GetHeight(&boldHeight);
    SetHighColor(text);
    BString headingText(heading.c_str());
    TruncateString(&headingText, B_TRUNCATE_END, bounds.right - textLeft - margin);
    float lineTop = y + (subtitle.empty() ? Scaled(8) : 0);
    DrawString(headingText.String(), BPoint(textLeft, lineTop + boldHeight.ascent));
    SetFont(be_plain_font);
    if (!subtitle.empty()) {
        SetHighColor(WeakTextColor());
        BString subtitleText(subtitle.c_str());
        TruncateString(&subtitleText, B_TRUNCATE_END, bounds.right - textLeft - margin);
        DrawString(subtitleText.String(), BPoint(textLeft, lineTop + RowHeight(*be_bold_font)
            + plainHeight.ascent));
    }
    y += std::max(RowHeight(*be_bold_font) + plainRow, Scaled(24)) + Scaled(8);

    // The forwarded port.
    fPortRect = BRect();
    if (fStatus.state == VpnState::Connected && fStatus.forwardedPort != 0) {
        std::string port = std::to_string(fStatus.forwardedPort);
        float x = textLeft;
        BRect portIcon(x, y + (plainRow - Scaled(16)) / 2, x + Scaled(16) - 1,
            y + (plainRow - Scaled(16)) / 2 + Scaled(16) - 1);
        Icons::Draw(this, Icons::Get("active-port"), portIcon);
        x = portIcon.right + Scaled(6);
        SetHighColor(WeakTextColor());
        DrawString("Active port:", BPoint(x, y + plainHeight.ascent));
        x += StringWidth("Active port: ");
        SetHighColor(text);
        SetFont(be_bold_font);
        DrawString(port.c_str(), BPoint(x, y + plainHeight.ascent));
        x += StringWidth(port.c_str()) + Scaled(6);
        SetFont(be_plain_font);
        BRect copy(x, portIcon.top, x + Scaled(16) - 1, portIcon.bottom);
        Icons::Draw(this, Icons::Tinted("copy", WeakTextColor()), copy);
        fPortRect = BRect(portIcon.left, y, copy.right, y + plainRow);
        if (fCopied) {
            SetHighColor(SuccessColor());
            DrawString("Copied!", BPoint(copy.right + Scaled(8), y + plainHeight.ascent));
        }
    }
    SetDrawingMode(B_OP_COPY);
}


void StatusView::MouseDown(BPoint where)
{
    if (!fPortRect.IsValid() || !fPortRect.Contains(where))
        return;
    std::string port = std::to_string(fStatus.forwardedPort);
    if (be_clipboard->Lock()) {
        be_clipboard->Clear();
        BMessage* data = be_clipboard->Data();
        data->AddData("text/plain", B_MIME_TYPE, port.c_str(), port.size());
        be_clipboard->Commit();
        be_clipboard->Unlock();
    }
    fCopied = true;
    delete fCopiedTimer;
    BMessage done(kMsgCopiedDone);
    fCopiedTimer = new BMessageRunner(BMessenger(this), &done, 1500000, 1);
    Invalidate();
}
