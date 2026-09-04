@echo off
rem Builds typehelper.exe with MSVC.  Usage: build.bat [x64|arm64]
rem
rem The command lives in a .bat rather than in the CI step because
rem /MANIFESTUAC's value contains double quotes, and passing that through
rem `cmd /c "<vsdevcmd> && cl ..."` silently drops them -- the binary then links
rem fine and carries no uiAccess manifest, which shows up much later as
rem "uiAccess=0" and reads as the dialog refusing input rather than as a build
rem problem.
rem
rem /MANIFESTUAC rather than /MANIFESTINPUT with typehelper.manifest: the linker
rem emits its own snippet with uiAccess="false", and merging the two is fatal
rem (manifest authoring error c1010001 / LNK1327). typehelper.manifest stays for
rem the mingw path, which compiles it through typehelper.rc:
rem
rem   x86_64-w64-mingw32-windres typehelper.rc -O coff -o typehelper.res
rem   x86_64-w64-mingw32-gcc -municode -O2 -o typehelper.exe typehelper.c typehelper.res -luser32
setlocal

set ARCH=%~1
if "%ARCH%"=="" set ARCH=x64

for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set VSPATH=%%i
if not defined VSPATH (
  echo vswhere found no Visual Studio installation
  exit /b 1
)

call "%VSPATH%\Common7\Tools\VsDevCmd.bat" -arch=%ARCH% -no_logo
if errorlevel 1 exit /b 1

cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS typehelper.c /Fe:typehelper.exe ^
   /link user32.lib shell32.lib advapi32.lib ^
   /MANIFEST:EMBED /MANIFESTUAC:"level='asInvoker' uiAccess='true'"
if errorlevel 1 exit /b 1

echo built typehelper.exe for %ARCH%
