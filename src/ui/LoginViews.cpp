#include "LoginViews.h"
#include "Icons.h"
#include "Messages.h"
#include "Widgets.h"
#include "core/Util.h"
#include <Button.h>
#include <CheckBox.h>
#include <ControlLook.h>
#include <LayoutBuilder.h>
#include <StringView.h>
#include <TextControl.h>
#include <Window.h>

namespace {

const uint32 kMsgFieldChanged = 'fchg';
const uint32 kMsgShowPassword = 'shpw';
const uint32 kMsgToggleRecovery = 'trec';

const char kSignupUrl[] = "https://account.protonvpn.com/signup?ref=linux";
const char kHelpUrl[] = "https://protonvpn.com/support";

}  // namespace


LoginView::LoginView()
    :
    BView("login", 0)
{
    float spacing = be_control_look->DefaultItemSpacing();
    fUsername = new BTextControl("username", "Username:", "", new BMessage(kMsgLogin));
    fUsername->SetModificationMessage(new BMessage(kMsgFieldChanged));
    fPassword = new BTextControl("password", "Password:", "", new BMessage(kMsgLogin));
    fPassword->SetModificationMessage(new BMessage(kMsgFieldChanged));
    fPassword->TextView()->HideTyping(true);
    fShowPassword = new BCheckBox("show", "Show password", new BMessage(kMsgShowPassword));
    fSignIn = new BButton("sign in", "Sign in", new BMessage(kMsgLogin));
    fSignIn->SetEnabled(false);

    LinkView* create = new LinkView("create", "Create Account", kSignupUrl);
    LinkView* help = new LinkView("help", "Need Help?", kHelpUrl);
    help->SetAlignment(B_ALIGN_RIGHT);

    fForm = new BView("form", 0);
    BLayoutBuilder::Group<>(fForm, B_VERTICAL, spacing)
        .AddGlue(1)
        .Add(new PictureView("logo", "logo", roundf(280 * Icons::Scale())))
        .AddStrut(spacing * 2)
        .AddGrid(spacing, spacing)
            .AddTextControl(fUsername, 0, 0)
            .AddTextControl(fPassword, 0, 1)
            .Add(fShowPassword, 1, 2)
        .End()
        .AddStrut(spacing)
        .AddGroup(B_HORIZONTAL)
            .AddGlue()
            .Add(fSignIn)
            .AddGlue()
        .End()
        .AddGlue(2)
        .AddGroup(B_HORIZONTAL)
            .Add(create)
            .AddGlue()
            .Add(help)
        .End();

    BStringView* message = new BStringView("blocking", "Kill switch is blocking any outgoing connections.");
    BButton* disable = new BButton("disable", "Disable", new BMessage(kMsgDisableKillSwitch));
    fBanner = new BView("banner", 0);
    BLayoutBuilder::Group<>(fBanner, B_HORIZONTAL, spacing)
        .SetInsets(spacing)
        .Add(message)
        .AddGlue()
        .Add(disable);
    fBanner->Hide();

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .SetInsets(spacing * 3, spacing * 2, spacing * 3, spacing * 2)
        .Add(fForm)
        .Add(fBanner);
}


void LoginView::AttachedToWindow()
{
    BView::AttachedToWindow();
    AdoptParentColors();
    fUsername->SetTarget(this);
    fPassword->SetTarget(this);
    fShowPassword->SetTarget(this);
    fSignIn->SetTarget(this);
    StyleButton(fSignIn, AccentColor());
}


void LoginView::UpdateButton()
{
    bool ready = !pvpn::Trim(fUsername->Text()).empty() && !pvpn::Trim(fPassword->Text()).empty();
    fSignIn->SetEnabled(ready && !fBusy);
}


void LoginView::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgFieldChanged:
            UpdateButton();
            break;
        case kMsgShowPassword:
            fPassword->TextView()->HideTyping(fShowPassword->Value() != B_CONTROL_ON);
            break;
        case kMsgLogin: {
            if (!fSignIn->IsEnabled())
                break;
            BMessage login(kMsgLogin);
            login.AddString("username", pvpn::Trim(fUsername->Text()).c_str());
            login.AddString("password", fPassword->Text());
            Window()->PostMessage(&login);
            break;
        }
        default:
            BView::MessageReceived(message);
    }
}


void LoginView::Reset()
{
    fUsername->SetText("");
    fPassword->SetText("");
    fShowPassword->SetValue(B_CONTROL_OFF);
    fPassword->TextView()->HideTyping(true);
    SetBusy(false);
    fUsername->MakeFocus(true);
}


void LoginView::SetBusy(bool busy)
{
    fBusy = busy;
    fUsername->SetEnabled(!busy);
    fPassword->SetEnabled(!busy);
    UpdateButton();
}


void LoginView::SetKillSwitchBlocking(bool blocking)
{
    if (blocking && fBanner->IsHidden())
        fBanner->Show();
    else if (!blocking && !fBanner->IsHidden())
        fBanner->Hide();
    fUsername->SetEnabled(!blocking && !fBusy);
    fPassword->SetEnabled(!blocking && !fBusy);
    fShowPassword->SetEnabled(!blocking);
    if (blocking)
        fSignIn->SetEnabled(false);
    else
        UpdateButton();
}


TwoFactorView::TwoFactorView()
    :
    BView("two factor", 0)
{
    float spacing = be_control_look->DefaultItemSpacing();
    BStringView* heading = new BStringView("heading", "Two-factor authentication");
    BFont font(be_bold_font);
    font.SetSize(be_bold_font->Size() * 1.25f);
    heading->SetFont(&font);
    heading->SetAlignment(B_ALIGN_CENTER);
    fLabel = new BStringView("label", "");
    fCode = new BTextControl("code", nullptr, "", new BMessage(kMsgSubmitTwoFactor));
    fCode->SetModificationMessage(new BMessage(kMsgFieldChanged));
    fClarification = new DescriptionView("clarification", "");
    fAuthenticate = new BButton("authenticate", "Authenticate", new BMessage(kMsgSubmitTwoFactor));
    fToggle = new BButton("toggle", "Use recovery code", new BMessage(kMsgToggleRecovery));
    fCancel = new BButton("cancel", "Cancel", new BMessage(kMsgCancelTwoFactor));
    fAuthenticate->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));
    fToggle->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));
    fCancel->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));

    BLayoutBuilder::Group<>(this, B_VERTICAL, spacing)
        .SetInsets(spacing * 3, spacing * 2, spacing * 3, spacing * 2)
        .AddGlue(1)
        .Add(new PictureView("logo", "logo", roundf(200 * Icons::Scale())))
        .AddStrut(spacing)
        .Add(heading)
        .AddStrut(spacing)
        .Add(fLabel)
        .Add(fCode)
        .Add(fClarification)
        .AddStrut(spacing)
        .Add(fAuthenticate)
        .Add(fToggle)
        .Add(fCancel)
        .AddGlue(2);
    UpdateMode();
}


void TwoFactorView::AttachedToWindow()
{
    BView::AttachedToWindow();
    AdoptParentColors();
    fCode->SetTarget(this);
    fAuthenticate->SetTarget(this);
    fToggle->SetTarget(this);
    fCancel->SetTarget(Window());
    StyleButton(fAuthenticate, AccentColor());
    StyleButton(fCancel, DangerColor());
}


void TwoFactorView::UpdateMode()
{
    if (fRecovery) {
        fLabel->SetText("Recovery code");
        fClarification->SetDescription("Each code can only be used once");
        fToggle->SetLabel("Use 6-digit authentication code");
    } else {
        fLabel->SetText("6-digit authentication code");
        fClarification->SetDescription("");
        fToggle->SetLabel("Use recovery code");
    }
    UpdateButton();
}


void TwoFactorView::UpdateButton()
{
    size_t length = pvpn::Trim(fCode->Text()).size();
    fAuthenticate->SetEnabled(!fBusy && length == (fRecovery ? 8u : 6u));
}


void TwoFactorView::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgFieldChanged:
            UpdateButton();
            break;
        case kMsgToggleRecovery:
            fRecovery = !fRecovery;
            UpdateMode();
            fCode->MakeFocus(true);
            break;
        case kMsgSubmitTwoFactor: {
            if (!fAuthenticate->IsEnabled())
                break;
            BMessage submit(kMsgSubmitTwoFactor);
            submit.AddString("code", pvpn::Trim(fCode->Text()).c_str());
            Window()->PostMessage(&submit);
            break;
        }
        default:
            BView::MessageReceived(message);
    }
}


void TwoFactorView::Reset()
{
    fCode->SetText("");
    fRecovery = false;
    SetBusy(false);
    UpdateMode();
    fCode->MakeFocus(true);
}


void TwoFactorView::SetBusy(bool busy)
{
    fBusy = busy;
    fCode->SetEnabled(!busy);
    fToggle->SetEnabled(!busy);
    fCancel->SetEnabled(!busy);
    if (!busy)
        fCode->SetText("");
    UpdateButton();
}


LoadingView::LoadingView()
    :
    BView("loading", 0)
{
    fText = new BStringView("text", "");
    fText->SetAlignment(B_ALIGN_CENTER);
    fSpinner = new Spinner(roundf(48 * Icons::Scale()));
    float spacing = be_control_look->DefaultItemSpacing();
    BLayoutBuilder::Group<>(this, B_VERTICAL, spacing * 2)
        .AddGlue()
        .Add(fText)
        .AddGroup(B_HORIZONTAL)
            .AddGlue()
            .Add(fSpinner)
            .AddGlue()
        .End()
        .AddGlue();
}


void LoadingView::SetText(const char* text)
{
    fText->SetText(text);
}


void LoadingView::Show()
{
    BView::Show();
    fSpinner->Start();
}


void LoadingView::Hide()
{
    fSpinner->Stop();
    BView::Hide();
}
