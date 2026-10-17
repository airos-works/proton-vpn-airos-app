#include "BugReportWindow.h"
#include "App.h"
#include "MainWindow.h"
#include "Messages.h"
#include "Widgets.h"
#include "core/Util.h"
#include <Button.h>
#include <CheckBox.h>
#include <ControlLook.h>
#include <LayoutBuilder.h>
#include <ScrollView.h>
#include <StringView.h>
#include <TextControl.h>
#include <TextView.h>
#include <regex>
#include <thread>

using namespace pvpn;

namespace {

const uint32 kMsgChanged = 'brch';
const uint32 kMsgSubmit = 'brsb';
const uint32 kMsgCancel = 'brcn';
const char kVersion[] = "0.1.0";

class ChangeTextView : public BTextView {
public:
    ChangeTextView(BHandler* target) : BTextView("description"), fTarget(target) {}

protected:
    void InsertText(const char* text, int32 length, int32 offset,
        const text_run_array* runs) override
    {
        BTextView::InsertText(text, length, offset, runs);
        Notify();
    }

    void DeleteText(int32 start, int32 finish) override
    {
        BTextView::DeleteText(start, finish);
        Notify();
    }

private:
    void Notify()
    {
        if (Window() != nullptr)
            Window()->PostMessage(kMsgChanged, fTarget);
    }

    BHandler* fTarget;
};

}  // namespace


BugReportWindow::BugReportWindow(BRect parentFrame, const char* username, const std::string& logPath)
    :
    BWindow(BRect(0, 0, 400, 300), "Report an Issue", B_TITLED_WINDOW,
        B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE),
    fLogPath(logPath)
{
    float spacing = be_control_look->DefaultItemSpacing();
    fNotification = new NotificationBar();
    fUsername = new BTextControl("username", "Username:", username, nullptr);
    fUsername->SetModificationMessage(new BMessage(kMsgChanged));
    fEmail = new BTextControl("email", "Email:", "", nullptr);
    fEmail->SetModificationMessage(new BMessage(kMsgChanged));
    fDescription = new ChangeTextView(this);
    fDescription->SetWordWrap(true);
    BScrollView* scroll = new BScrollView("scroll", fDescription, 0, false, true);
    scroll->SetExplicitMinSize(BSize(B_SIZE_UNSET, be_plain_font->Size() * 8));
    fSendLogs = new BCheckBox("logs", "Send error logs", nullptr);
    fSendLogs->SetValue(B_CONTROL_ON);
    fCancel = new BButton("cancel", "Cancel", new BMessage(kMsgCancel));
    fSubmit = new BButton("submit", "Submit", new BMessage(kMsgSubmit));
    fSubmit->SetEnabled(false);

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(fNotification)
        .AddGroup(B_VERTICAL, spacing)
            .SetInsets(spacing * 2)
            .AddGrid(spacing, spacing)
                .AddTextControl(fUsername, 0, 0)
                .AddTextControl(fEmail, 0, 1)
            .End()
            .Add(new BStringView("description label", "Description (minimum 50 characters)"))
            .Add(scroll, 10)
            .Add(fSendLogs)
            .AddGroup(B_HORIZONTAL)
                .AddGlue()
                .Add(fCancel)
                .Add(fSubmit)
            .End()
        .End();
    fNotification->Hide();
    float scale = be_plain_font->Size() / 12.0f;
    ResizeTo(420 * scale, 380 * scale);
    CenterIn(parentFrame);
    StyleButton(fSubmit, AccentColor());
    StyleButton(fCancel, DangerColor());
}


void BugReportWindow::UpdateButton()
{
    static const std::regex kEmail("[^@\\s]+@[^@\\s]{2,}\\.[^@\\s\\.-]{2,}");
    bool ok = !Trim(fUsername->Text()).empty()
        && std::regex_match(std::string(fEmail->Text()), kEmail)
        && strlen(fDescription->Text()) > 50;
    fSubmit->SetEnabled(ok);
}


void BugReportWindow::SetFormEnabled(bool enabled)
{
    fUsername->SetEnabled(enabled);
    fEmail->SetEnabled(enabled);
    fDescription->MakeEditable(enabled);
    fSendLogs->SetEnabled(enabled);
    fCancel->SetEnabled(enabled);
    if (enabled)
        UpdateButton();
    else
        fSubmit->SetEnabled(false);
}


void BugReportWindow::MessageReceived(BMessage* message)
{
    switch (message->what) {
        case kMsgChanged:
            UpdateButton();
            break;
        case kMsgCancel:
            Quit();
            break;
        case kMsgSubmit: {
            fNotification->Show("Reporting your issue...", kNotificationInfo, 60000000);
            SetFormEnabled(false);
            std::string username = Trim(fUsername->Text());
            std::string email = Trim(fEmail->Text());
            std::string description = fDescription->Text();
            std::vector<std::string> attachments;
            if (fSendLogs->Value() == B_CONTROL_ON) {
                attachments.push_back(fLogPath);
                attachments.push_back("/var/log/syslog");
            }
            BMessenger target(this);
            std::thread([=]() {
                ApiResult result = ProtonApp::Get()->Client().SubmitBugReport(username, email,
                    description, attachments, kVersion);
                BMessage reply(kMsgBugReportResult);
                reply.AddInt32("error", (int32)result.error);
                reply.AddString("message", result.message.c_str());
                target.SendMessage(&reply);
            }).detach();
            break;
        }
        case kMsgBugReportResult: {
            ApiError error = (ApiError)message->GetInt32("error", 0);
            if (error == ApiError::None) {
                BMessage done(kMsgNotice);
                // The main window shows the confirmation.
                for (int32 i = 0; BWindow* window = be_app->WindowAt(i); i++) {
                    if (MainWindow* main = dynamic_cast<MainWindow*>(window)) {
                        if (main->LockLooper()) {
                            main->Notify("Your issue has been reported", kNotificationSuccess);
                            main->UnlockLooper();
                        }
                    }
                }
                Quit();
                return;
            }
            SetFormEnabled(true);
            if (error == ApiError::NotReachable)
                fNotification->Show("Proton services could not be reached.\nPlease try again.",
                    kNotificationError);
            else if (error == ApiError::Api && strlen(message->GetString("message", "")) > 0)
                fNotification->Show(message->GetString("message", ""), kNotificationError);
            else
                fNotification->Show("Something went wrong. Please try submitting your report at:\n"
                    "https://protonvpn.com/support-form", kNotificationError);
            break;
        }
        default:
            BWindow::MessageReceived(message);
    }
}
