; Installer Windows per CorianoSign (Inno Setup).
;
; Compila con Inno Setup (gratuito: https://jrsoftware.org/isdl.php):
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DMyAppVersion=0.2.0 packaging\installer_windows.iss
; oppure usa lo script helper:  packaging\make_installer_windows.ps1
;
; Prerequisito: dist\CorianoSign\ già compilata (packaging\build_windows.ps1).

#ifndef MyAppVersion
  #define MyAppVersion "0.2.0"
#endif
#define MyAppName "CorianoSign"
#define MyAppExe "CorianoSign.exe"
#define MyAppPublisher "Comune di Coriano"

[Setup]
AppId={{A7F3C1E2-9B4D-4E7A-8C21-CORIANOSIGN01}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; installa per l'utente corrente se non si hanno privilegi admin
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename={#MyAppName}-{#MyAppVersion}-setup
SetupIconFile=CorianoSign.ico
UninstallDisplayIcon={app}\{#MyAppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"

[Tasks]
Name: "desktopicon"; Description: "Crea un'icona sul desktop"; GroupDescription: "Icone aggiuntive:"; Flags: unchecked
Name: "assocp7m"; Description: "Apri i file .p7m con CorianoSign"; GroupDescription: "Associazioni file:"

[Files]
; l'intera cartella onedir prodotta da PyInstaller
Source: "..\dist\CorianoSign\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{group}\Disinstalla {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Registry]
; associazione file .p7m (solo se il task assocp7m è selezionato)
Root: HKA; Subkey: "Software\Classes\.p7m\OpenWithProgids"; ValueType: string; ValueName: "CorianoSign.p7m"; ValueData: ""; Flags: uninsdeletevalue; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\CorianoSign.p7m"; ValueType: string; ValueName: ""; ValueData: "File firmato PKCS#7 (CAdES)"; Flags: uninsdeletekey; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\CorianoSign.p7m\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExe},0"; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\CorianoSign.p7m\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExe}"" ""%1"""; Tasks: assocp7m

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Avvia {#MyAppName}"; Flags: nowait postinstall skipifsilent
