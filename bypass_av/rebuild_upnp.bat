@echo off
REM ============================================================
REM  rebuild_upnp.bat
REM
REM  DEPRECATED - kept as a thin wrapper for backward compat.
REM  Use build.bat directly:
REM      build.bat upnp
REM ============================================================
setlocal
cd /d "%~dp0"
call build.bat upnp %*
exit /b %errorlevel%
