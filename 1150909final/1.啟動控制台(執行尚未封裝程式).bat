@echo off
:: 強制切換為 UTF-8 編碼
chcp 65001 >nul
cd /d "%~dp0"

:: 檢查是否具備管理員權限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] 正在以系統管理員權限重新啟動...
    :: 使用變數並透過跳脫引號傳遞完整路徑，防止 # 與 () 特殊字元被解析為註解或語法錯誤
    powershell -NoProfile -Command "$path = [System.IO.Path]::GetFullPath('%~f0'); Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('\"\"' + $path + '\"\"') -Verb RunAs"
    exit /b
)

echo [INFO] 正在啟動 IIS 憑證自動化管理工具...
:: 使用 -Sta 確保 WPF UI 執行緒穩定，路徑以雙引號封裝防止特殊字元截斷
powershell -NoProfile -Sta -ExecutionPolicy Bypass -File "%~dp0IIS憑證自動管理工具.ps1"

:: 若執行異常中斷，保留視窗以供查看錯誤訊息
if %errorlevel% neq 0 (
    echo.
    echo ===================================================
    echo [ERROR] 程式異常退出，請查看上方紅字或提示訊息。
    echo ===================================================
    pause
)