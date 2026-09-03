@echo off
REM ============================================================
REM  rebuild_tunnel.bat
REM
REM  DEPRECATED - kept as a thin wrapper for backward compat.
REM  Use build.bat directly:
REM      build.bat tunnel ^<tunnel_ip^> [reg_port]
REM ============================================================
setlocal
cd /d "%~dp0"
call build.bat tunnel %*
exit /b %errorlevel%
