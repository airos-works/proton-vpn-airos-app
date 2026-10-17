// Message codes shared by the app, its windows and the Deskbar tray icon.
#pragma once
#include <SupportDefs.h>

extern const char* const kAppSignature;      // "application/x-vnd.ProtonVPN"

enum {
    // Results of work done on worker threads.
    kMsgLoginResult = 'lgrs',
    kMsgTwoFactorResult = '2fas',
    kMsgSessionLoaded = 'sesl',
    kMsgLogoutResult = 'lgot',
    kMsgAccountRefreshed = 'acrf',
    kMsgConnectResult = 'cnrs',
    kMsgBugReportResult = 'bugr',

    // Core events, posted from the core's threads to the app.
    kMsgVpnStatus = 'vpst',
    kMsgServerListChanged = 'svch',
    kMsgAccountChanged = 'acch',
    kMsgNotice = 'notc',
    kMsgLog = 'logl',

    // Commands (menus, buttons, the tray icon, scripting).
    kMsgLogin = 'lgin',
    kMsgSubmitTwoFactor = 'sb2f',
    kMsgCancelTwoFactor = 'cn2f',
    kMsgQuickConnect = 'qcon',
    kMsgDisconnect = 'dcon',
    kMsgConnectCountry = 'ccty',
    kMsgConnectLocation = 'cloc',
    kMsgConnectSecureCore = 'csec',
    kMsgConnectServer = 'csrv',
    kMsgConnectCode = 'ccod',     // "code": FASTEST, NL#42 or US (tray pins)
    kMsgChangeServer = 'chsv',
    kMsgSignOut = 'sout',
    kMsgShowSettings = 'sett',
    kMsgShowAbout = 'abou',
    kMsgShowReleaseNotes = 'rnot',
    kMsgShowBugReport = 'bugs',
    kMsgShowWindow = 'show',
    kMsgToggleWindow = 'togw',
    kMsgOpenUrl = 'ourl',         // "url"
    kMsgSettingsChanged = 'setc', // a Settings window edit, "settings" (JSON)
    kMsgAppConfigChanged = 'apcf',
    kMsgRefreshAccount = 'rfac',
    kMsgFocusSearch = 'fsrc',
    kMsgDisableKillSwitch = 'dkil',
    kMsgCopyPort = 'cprt',
    kMsgRefreshServers = 'rfsv',
    kMsgServersRefreshed = 'rfsd',

    // Window-internal.
    kMsgHideNotification = 'hnot',
    kMsgSearchChanged = 'srch',
    kMsgSearchInvoked = 'srci',
    kMsgListActivity = 'lact',
    kMsgSpinner = 'spin',
    kMsgCooldownTick = 'cdtk',

    // Tray icon <-> app.
    kMsgGetTrayState = 'gtry',
    kMsgTrayState = 'tray',
};
