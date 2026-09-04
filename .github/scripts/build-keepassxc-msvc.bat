@echo off
rem Configures and builds KeePassXC with MSVC.  Usage: build-keepassxc-msvc.bat <arch>
rem
rem Everything runs inside VsDevCmd and names cl explicitly. Left to itself,
rem CMake picked up the mingw gcc that ships on the runner's PATH and the link
rem step failed with
rem
rem   collect2.exe: error: ld returned 1 exit status
rem
rem because vcpkg had built x64-windows-static libraries with MSVC and Qt is the
rem msvc2022_64 build -- three toolchains, one of them chosen by accident.
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

cmake -S . -B build -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=cl ^
  -DCMAKE_CXX_COMPILER=cl ^
  -DCMAKE_TOOLCHAIN_FILE="%VCPKG_INSTALLATION_ROOT%\scripts\buildsystems\vcpkg.cmake" ^
rem Dynamic CRT, not -static: vcpkg's static triplet builds botan with /MT while
rem Qt from aqt and KeePassXC's own objects are /MD, and the link fails with
rem   botan-3.lib: error LNK2038: mismatch detected for 'RuntimeLibrary':
rem   'MT_StaticRelease' doesn't match 'MD_DynamicRelease'
  -DVCPKG_TARGET_TRIPLET=%ARCH%-windows ^
  -DCMAKE_PREFIX_PATH="%QT_PREFIX%" ^
  -DWITH_TESTS=OFF ^
  -DWITH_XC_AUTOTYPE=ON ^
  -DKPXC_FEATURE_DOCS=OFF
if errorlevel 1 exit /b 1

cmake --build build --parallel
if errorlevel 1 exit /b 1

echo build finished for %ARCH%
