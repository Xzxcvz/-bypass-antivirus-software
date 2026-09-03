@echo off
chcp 65001 >nul
title WindowsUpdate 恢复工具
echo ============================================
echo   WindowsUpdate 恶搞恢复工具
echo   以管理员身份运行才能完全恢复
echo ============================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 请右键 → "以管理员身份运行"
    pause
    exit /b 1
)

echo [1/5] 正在关闭进程...
taskkill /f /im runtime.exe >nul 2>&1
taskkill /f /im bypass.exe >nul 2>&1
taskkill /f /im WindowsUpdate.exe >nul 2>&1
echo     OK

echo [2/5] 正在恢复 UAC...
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f >nul
echo     OK（可能需要重启才能完全生效）

echo [3/5] 正在删除开机启动...
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdate /f >nul 2>&1
echo     OK

echo [4/5] 正在清理文件...
rmdir /s /q "%APPDATA%\Microsoft\Windows\Caches" >nul 2>&1
echo     OK

echo [5/5] 正在恢复原始文件...
if exist "%USERPROFILE%\Desktop\WindowsUpdate.exe.bak" (
    move /y "%USERPROFILE%\Desktop\WindowsUpdate.exe.bak" "%USERPROFILE%\Desktop\WindowsUpdate.exe" >nul
    echo     已恢复桌面上的 WindowsUpdate.exe
)
if exist "%USERPROFILE%\Downloads\WindowsUpdate.exe.bak" (
    move /y "%USERPROFILE%\Downloads\WindowsUpdate.exe.bak" "%USERPROFILE%\Downloads\WindowsUpdate.exe" >nul
    echo     已恢复下载目录中的 WindowsUpdate.exe
)

echo.
echo ============================================
echo  恢复完成！
echo  建议重启电脑以确保 UAC 完全生效。
echo ============================================
pause
