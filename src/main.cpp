// Proton VPN for air/OS (Haiku).
#include "ui/App.h"
#include <csignal>

int main()
{
    signal(SIGPIPE, SIG_IGN);
    ProtonApp app;
    app.Run();
    return 0;
}
