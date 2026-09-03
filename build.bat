@echo off
REM Build script for payload_reconstructed
REM Requires: Visual Studio Build Tools or MSVC

echo === Building payload_reconstructed.c ===
cl /nologo /O1 /GS- /W4 /D "_CRT_SECURE_NO_WARNINGS" payload_reconstructed.c /link /subsystem:windows /out:payload_reconstructed.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] Success: payload_reconstructed.exe
) else (
    echo [-] Build failed
)

echo.
echo === Building payload_shellcode.c ===
cl /nologo /O1 /GS- /W4 /D "_CRT_SECURE_NO_WARNINGS" payload_shellcode.c /link /subsystem:windows /out:payload_shellcode.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] Success: payload_shellcode.exe
) else (
    echo [-] Build failed
)

echo.
echo Done.
