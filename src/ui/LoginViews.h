// The signed-out screens: the login form, the two-factor form (authenticator
// app codes and recovery codes; Haiku has no FIDO2 library, so no security
// keys, as the GTK app without one) and the loading screen.
#pragma once
#include <View.h>

class BButton;
class BCheckBox;
class BStringView;
class BTextControl;
class DescriptionView;
class Spinner;

class LoginView : public BView {
public:
    LoginView();

    void AttachedToWindow() override;
    void MessageReceived(BMessage* message) override;
    void Reset();
    void SetBusy(bool busy);
    // The permanent kill switch banner ("Kill switch is blocking...").
    void SetKillSwitchBlocking(bool blocking);

private:
    void UpdateButton();

    BTextControl* fUsername;
    BTextControl* fPassword;
    BCheckBox* fShowPassword;
    BButton* fSignIn;
    BView* fBanner;
    BView* fForm;
    bool fBusy = false;
};

class TwoFactorView : public BView {
public:
    TwoFactorView();

    void AttachedToWindow() override;
    void MessageReceived(BMessage* message) override;
    void Reset();
    void SetBusy(bool busy);

private:
    void UpdateMode();
    void UpdateButton();

    BStringView* fLabel;
    BTextControl* fCode;
    DescriptionView* fClarification;
    BButton* fAuthenticate;
    BButton* fToggle;
    BButton* fCancel;
    bool fRecovery = false;
    bool fBusy = false;
};

class LoadingView : public BView {
public:
    LoadingView();

    void SetText(const char* text);
    void Show() override;
    void Hide() override;

private:
    BStringView* fText;
    Spinner* fSpinner;
};
