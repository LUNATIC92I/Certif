; Script Inno Setup 6 – programme d'installation Windows 10/11 x64 d'AI SOC ANALYST
; Compilation : ISCC.exe packaging\AI_SOC_ANALYST.iss   (après le build PyInstaller dans dist\AI_SOC_ANALYST)
#define AppName "AI SOC ANALYST"
#define AppVersion "1.0.0"
#define AppExe "AI_SOC_ANALYST.exe"
#define SrcDir "..\dist\AI_SOC_ANALYST"

[Setup]
AppId={{6C1F5D2E-8B7A-4C1D-9E3F-2A4B5C6D7E81}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=AI SOC ANALYST
DefaultDirName={autopf}\AI_SOC_ANALYST
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=AI_SOC_ANALYST_Setup_{#AppVersion}
SetupIconFile=..\src\ai_soc_analyst\resources\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
LicenseFile=..\docs\LICENCE_ET_AVERTISSEMENT.txt

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\docs\*.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Guide utilisateur"; Filename: "{app}\docs\USER_GUIDE.md"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; Les données utilisateur (%LOCALAPPDATA%\AI_SOC_ANALYST : base, rapports, quarantaine) sont volontairement conservées
; à la désinstallation : ce sont des preuves d'investigation. Supprimez ce dossier manuellement si nécessaire.
