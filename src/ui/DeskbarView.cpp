#include "DeskbarView.h"
#include "Messages.h"
#include "core/Connector.h"
#include <Bitmap.h>
#include <DataIO.h>
#include <Deskbar.h>
#include <File.h>
#include <MenuItem.h>
#include <MessageRunner.h>
#include <PopUpMenu.h>
#include <Resources.h>
#include <Roster.h>
#include <TranslationUtils.h>
#include <Window.h>
#include <image.h>

using pvpn::VpnState;

const char* ProtonDeskbarView::kName = "Proton VPN";

namespace {

const uint32 kMsgPoll = 'poll';

// The executable this code was loaded from (inside Deskbar's team).
bool OwnImagePath(BString& path)
{
    image_info info;
    int32 cookie = 0;
    addr_t self = (addr_t)&OwnImagePath;
    while (get_next_image_info(B_CURRENT_TEAM, &cookie, &info) == B_OK) {
        if (self >= (addr_t)info.text && self < (addr_t)info.text + info.text_size) {
            path = info.name;
            return true;
        }
    }
    return false;
}

BBitmap* LoadPng(BResources& resources, const char* name)
{
    size_t size = 0;
    const void* data = resources.LoadResource('PNG ', name, &size);
    if (data == nullptr)
        return nullptr;
    BMemoryIO io(data, size);
    return BTranslationUtils::GetBitmap(&io);
}

}  // namespace


ProtonDeskbarView::ProtonDeskbarView(BRect frame)
    :
    BView(frame, kName, B_FOLLOW_LEFT | B_FOLLOW_TOP, B_WILL_DRAW)
{
    Init();
}


ProtonDeskbarView::ProtonDeskbarView(BMessage* archive)
    :
    BView(archive)
{
    Init();
}


ProtonDeskbarView::~ProtonDeskbarView()
{
    delete fConnected;
    delete fDisconnected;
    delete fError;
    delete fPoller;
}


void ProtonDeskbarView::Init()
{
    BString path;
    if (!OwnImagePath(path))
        return;
    BFile file(path.String(), B_READ_ONLY);
    BResources resources;
    if (resources.SetTo(&file) != B_OK)
        return;
    fConnected = LoadPng(resources, "icon:state-connected");
    fDisconnected = LoadPng(resources, "icon:state-disconnected");
    fError = LoadPng(resources, "icon:state-error");
}


BArchivable* ProtonDeskbarView::Instantiate(BMessage* archive)
{
    if (!validate_instantiation(archive, "ProtonDeskbarView"))
        return nullptr;
    return new ProtonDeskbarView(archive);
}


status_t ProtonDeskbarView::Archive(BMessage* archive, bool deep) const
{
    status_t status = BView::Archive(archive, deep);
    if (status == B_OK)
        status = archive->AddString("add_on", kAppSignature);
    if (status == B_OK)
        status = archive->AddString("class", "ProtonDeskbarView");
    return status;
}


void ProtonDeskbarView::AttachedToWindow()
{
    BView::AttachedToWindow();
    AdoptParentColors();
    if (ViewUIColor() == B_NO_COLOR)
        SetViewColor(Parent() != nullptr ? Parent()->ViewColor() : B_TRANSPARENT_COLOR);
    SetLowColor(ViewColor());
    BMessage poll(kMsgPoll);
    fPoller = new BMessageRunner(BMessenger(this), &poll, 2000000);
    Poll();
}


void ProtonDeskbarView::DetachedFromWindow()
{
    delete fPoller;
    fPoller = nullptr;
    BView::DetachedFromWindow();
}


void ProtonDeskbarView::Draw(BRect)
{
    BBitmap* icon = fDisconnected;
    VpnState state = (VpnState)fState;
    if (state == VpnState::Connected)
        icon = fConnected;
    else if (state == VpnState::Error)
        icon = fError;
    if (icon == nullptr)
        return;
    SetDrawingMode(B_OP_ALPHA);
    SetBlendingMode(B_PIXEL_ALPHA, B_ALPHA_OVERLAY);
    DrawBitmap(icon, icon->Bounds(), Bounds(), B_FILTER_BITMAP_BILINEAR);
    // Connecting: a small amber dot.
    if (fAppRunning && (state == VpnState::Connecting || state == VpnState::Disconnecting
            || fReconnecting)) {
        BRect bounds = Bounds();
        float radius = ceilf(bounds.Height() * 0.17f);
        BPoint center(bounds.right - radius - 0.5f, bounds.bottom - radius - 0.5f);
        SetDrawingMode(B_OP_OVER);
        SetHighColor(40, 40, 40);
        FillEllipse(center, radius + 1, radius + 1);
        SetHighColor(240, 160, 30);
        FillEllipse(center, radius, radius);
    }
}


void ProtonDeskbarView::MouseDown(BPoint where)
{
    ShowMenu(ConvertToScreen(where));
}


void ProtonDeskbarView::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgPoll:
            Poll();
            break;
        case kMsgTrayState: {
            int32 state = message->GetInt32("state", 0);
            bool reconnecting = message->GetBool("reconnecting", false);
            bool changed = state != fState || reconnecting != fReconnecting || !fAppRunning;
            fState = state;
            fReconnecting = reconnecting;
            fLoggedIn = message->GetBool("logged_in", false);
            fVisible = message->GetBool("visible", false);
            fPins.clear();
            const char* pin;
            for (int32 i = 0; message->FindString("pin", i, &pin) == B_OK; i++)
                fPins.push_back(pin);
            fAppRunning = true;
            if (changed)
                Invalidate();
            break;
        }
        default:
            BView::MessageReceived(message);
    }
}


void ProtonDeskbarView::Poll()
{
    BMessenger app(kAppSignature);
    if (app.IsValid()) {
        BMessage request(kMsgGetTrayState);
        app.SendMessage(&request, BMessenger(this), 500000);
    } else if (fAppRunning) {
        fAppRunning = false;
        fState = 0;
        Invalidate();
    }
}


void ProtonDeskbarView::ShowMenu(BPoint where)
{
    BPopUpMenu* menu = new BPopUpMenu("Proton VPN", false, false);
    menu->SetFont(be_plain_font);
    VpnState state = (VpnState)fState;
    if (fAppRunning && fLoggedIn) {
        if (state == VpnState::Disconnected || state == VpnState::Error
            || state == VpnState::Connecting) {
            BMenuItem* connect = new BMenuItem("Connect", new BMessage(kMsgQuickConnect));
            connect->SetEnabled(state != VpnState::Connecting && !fReconnecting);
            menu->AddItem(connect);
        }
        if (state == VpnState::Connected || state == VpnState::Disconnecting) {
            BMenuItem* disconnect = new BMenuItem("Disconnect", new BMessage(kMsgDisconnect));
            disconnect->SetEnabled(state == VpnState::Connected);
            menu->AddItem(disconnect);
        }
        menu->AddSeparatorItem();
        if (!fPins.empty()) {
            for (const std::string& pin : fPins) {
                BMessage* message = new BMessage(kMsgConnectCode);
                message->AddString("code", pin.c_str());
                menu->AddItem(new BMenuItem(pin.c_str(), message));
            }
            menu->AddSeparatorItem();
        }
    }
    if (fAppRunning) {
        menu->AddItem(new BMenuItem(fVisible ? "Hide" : "Show", new BMessage(kMsgToggleWindow)));
        menu->AddSeparatorItem();
        menu->AddItem(new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED)));
    } else {
        menu->AddItem(new BMenuItem("Open Proton VPN" B_UTF8_ELLIPSIS, new BMessage(kMsgShowWindow)));
        menu->AddItem(new BMenuItem("Remove from Deskbar", new BMessage('rmdb')));
    }

    BMenuItem* chosen = menu->Go(where, false, true);
    if (chosen != nullptr) {
        BMessage* message = chosen->Message();
        if (message->what == 'rmdb') {
            BDeskbar().RemoveItem(kName);
        } else {
            BMessenger app(kAppSignature);
            if (app.IsValid())
                app.SendMessage(message);
            else if (message->what == kMsgShowWindow)
                be_roster->Launch(kAppSignature);
        }
    }
    delete menu;
}


extern "C" _EXPORT BView* instantiate_deskbar_item(float maxWidth, float maxHeight)
{
    float size = floorf(maxHeight > 0 ? maxHeight : 16);
    return new ProtonDeskbarView(BRect(0, 0, size - 1, size - 1));
}
