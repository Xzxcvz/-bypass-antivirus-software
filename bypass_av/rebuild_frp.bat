@echo off
REM ============================================================
REM  rebuild_frp.bat
REM
REM  DEPRECATED - kept as a thin wrapper for backward compat.
REM  Use build.bat directly:
REM      build.bat frp ^<VPS_IP^> [vps_port] [remote_port]
REM ============================================================
setlocal
cd /d "%~dp0"
call build.bat frp %*
exit /b %errorlevel%
