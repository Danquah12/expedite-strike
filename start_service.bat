@echo off
:: Quick-start Expedite Strike as a background service
echo [*] Starting Expedite Strike Service...
schtasks /Run /TN "ExpediteStrike" 2>nul
if %ERRORLEVEL% equ 0 (
    echo [+] Service started! Access at http://localhost:9011/app/
) else (
    echo [!] Service not installed. Run install_service.bat as Administrator first.
    echo [*] Starting directly instead...
    start /B pythonw "%~dp0service_watchdog.py"
    echo [+] Started in background. Access at http://localhost:9011/app/
)
