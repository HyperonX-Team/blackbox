; Inno Setup script for the Blackbox Windows installer.
;
; Build with:
;   iscc /DAppVersion=0.2.0 /DStageDir=dist packaging\windows\blackbox.iss
;
; The installer is per-user (no admin prompt), puts both programs in
; %LOCALAPPDATA%\Programs\Blackbox and adds that directory to the user PATH.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef StageDir
  #define StageDir "dist"
#endif

[Setup]
AppId={{7C4B1E2A-3F6D-4B9A-9E21-5B0C8A2D6F31}
AppName=Blackbox
AppVersion={#AppVersion}
AppVerName=Blackbox {#AppVersion}
AppPublisher=The Blackbox Project
AppPublisherURL=https://github.com/HyperonX-Team/blackbox
AppSupportURL=https://github.com/HyperonX-Team/blackbox/issues
DefaultDirName={localappdata}\Programs\Blackbox
DefaultGroupName=Blackbox
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=blackbox-setup-windows-x86_64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
UninstallDisplayName=Blackbox

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#StageDir}\blackbox.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\blackbox-gui.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Blackbox";           Filename: "{app}\blackbox-gui.exe"
Name: "{group}\Uninstall Blackbox"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Blackbox";     Filename: "{app}\blackbox-gui.exe"; Tasks: desktopicon

; Put the install directory on the user PATH (only once).
[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\blackbox.exe"; Parameters: "doctor"; \
  Description: "Check the installation"; Flags: postinstall skipifsilent nowait

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

procedure RemoveFromPath();
var
  OrigPath, NewPath, Entry: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
    exit;
  Entry := ExpandConstant('{app}');
  NewPath := ';' + OrigPath + ';';
  P := Pos(';' + Uppercase(Entry) + ';', Uppercase(NewPath));
  if P > 0 then
  begin
    Delete(NewPath, P, Length(Entry) + 1);
    if (Length(NewPath) > 0) and (NewPath[1] = ';') then
      Delete(NewPath, 1, 1);
    if (Length(NewPath) > 0) and (NewPath[Length(NewPath)] = ';') then
      Delete(NewPath, Length(NewPath), 1);
    RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', NewPath);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath();
end;
