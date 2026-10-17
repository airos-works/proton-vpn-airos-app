// "Report an Issue": user name, email, a description of at least 50
// characters and (optionally) the app log and the system log, sent to
// Proton's support API as the GTK app does.
#pragma once
#include <Window.h>
#include <string>

class BButton;
class BCheckBox;
class BTextControl;
class BTextView;
class NotificationBar;

class BugReportWindow : public BWindow {
public:
    BugReportWindow(BRect parentFrame, const char* username, const std::string& logPath);

    void MessageReceived(BMessage* message) override;

private:
    void UpdateButton();
    void SetFormEnabled(bool enabled);

    NotificationBar* fNotification;
    BTextControl* fUsername;
    BTextControl* fEmail;
    BTextView* fDescription;
    BCheckBox* fSendLogs;
    BButton* fSubmit;
    BButton* fCancel;
    std::string fLogPath;
};
