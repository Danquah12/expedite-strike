@echo off
:: Stop Expedite Strike service
echo [*] Stopping Expedite Strike Service...

:: Create stop file for watchdog
echo stop > "%~dp0.stop_service"

:: End the scheduled task
schtasks /End /TN "ExpediteStrike" 2>nul

:: Kill any running python app.py processes on port 9011
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":9011" ^| findstr "LISTENING"') do (
    taskkill /PID %%p /F >nul 2>&1
)

echo [+] Service stopped.
