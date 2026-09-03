@echo off
REM ============================================================
REM  build_bypass.bat
REM
REM  DEPRECATED - kept as a thin wrapper for backward compat.
REM  Use build.bat directly:
REM      build.bat            same as plain bind-shell mode
REM      build.bat frp ^<ip^> embed frpc and tunnel via VPS
REM      build.bat tunnel     active tunnel mode
REM      build.bat upnp       UPnP auto-portmap
REM
REM  This wrapper just forwards to build.bat plain.
REM ============================================================
setlocal
cd /d "%~dp0"
call build.bat plain %*
exit /b %errorlevel%
