@echo off
REM ============================================================
REM  rebuild_with_vps.bat
REM
REM  DEPRECATED - kept as a thin wrapper for backward compat.
REM  Use build.bat directly:
REM      build.bat frp ^<VPS_IP^> [remote_port]
REM  (FRP mode is what the vps alias used to do; the vps key
REM   has been retired - the new flag is the more honest name.)
REM ============================================================
setlocal
cd /d "%~dp0"
REM legacy signature: rebuild_with_vps.bat <VPS_IP> [remote_port]
REM We forward as build.bat frp <VPS_IP> [7000] [remote_port].
set VPS_IP=%~1
set REMOTE_PORT=%~2
if "%REMOTE_PORT%"=="" set REMOTE_PORT=54321
call build.bat frp "%VPS_IP%" 7000 "%REMOTE_PORT%"
exit /b %errorlevel%
