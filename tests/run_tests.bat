@echo off
REM =================================================================
REM  tests\run_tests.bat
REM  Runs Python-level algorithm tests for XOR transport / FRP and
REM  djb2 hashing.
REM =================================================================
setlocal
cd /d "%~dp0\.."

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 tests\test_xor.py
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        python tests\test_xor.py
    ) else (
        echo [!] no python on PATH
        exit /b 2
    )
)

if %errorlevel% neq 0 (
    echo [!] tests failed
    exit /b 1
)
echo [+] tests passed
exit /b 0
