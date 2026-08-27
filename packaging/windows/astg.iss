#define MyAppName "AI Software Trust Gateway"
#define MyAppVersion "1.0.2"
#define MyAppPublisher "ASTG Team"
#define MyAppExeName "ASTG.exe"

[Setup]
AppId={{C0EC887B-3856-4AAF-9FD4-B7D2EC65D9A1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\AI Software Trust Gateway
DefaultGroupName=AI Software Trust Gateway
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\..\dist\installer
OutputBaseFilename=AI-Software-Trust-Gateway-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupLogging=yes

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "快捷方式："; Flags: checkedonce

[Files]
Source: "..\..\dist\windows-app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\AI Software Trust Gateway"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\AI Software Trust Gateway"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 AI Software Trust Gateway"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM ASTG.exe /F"; Flags: runhidden; RunOnceId: "StopASTG"
