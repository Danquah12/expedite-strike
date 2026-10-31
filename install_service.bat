@echo off
:: ═══════════════════════════════════════════════════════════════════════
:: Expedite Strike — Install as Windows Background Service
:: ═══════════════════════════════════════════════════════════════════════
:: This registers Expedite Strike as a Windows Scheduled Task that:
::   1. Starts automatically on system boot (before user login)
::   2. Runs continuously in the background
::   3. Auto-restarts if it crashes
::   4. Survives logouts, screen savers, and restarts
:: ═══════════════════════════════════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  EXPEDITE STRIKE — Service Installer                ║
echo  ║  Run as Administrator to install                    ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: Check for admin privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] This script must be run as Administrator!
    echo         Right-click and select "Run as administrator"
    pause
    exit /b 1
)

set SERVICE_NAME=ExpediteStrike
set PYTHON_EXE=C:\Python314\python.exe
set APP_DIR=D:\Software Engineering\Software-Engineering-Project-main\Software-Engineering-Project-main\tuhousing\AEGIS ON WINDOWS\app
set LOG_DIR=%APP_DIR%\logs

:: Create log directory
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:: Remove existing task if any
schtasks /Delete /TN "%SERVICE_NAME%" /F >nul 2>&1
echo [*] Cleaned up previous installation

:: Create the scheduled task
:: /SC ONSTART = runs at system startup (before login)
:: /RL HIGHEST = run with highest privileges
:: /DELAY 0000:30 = wait 30 seconds after boot for network
schtasks /Create ^
    /TN "%SERVICE_NAME%" ^
    /TR "\"%PYTHON_EXE%\" app.py" ^
    /SC ONSTART ^
    /RL HIGHEST ^
    /DELAY 0000:30 ^
    /RU SYSTEM ^
    /F

if %ERRORLEVEL% equ 0 (
    echo [+] Service registered: %SERVICE_NAME%
    echo [+] Will start automatically on boot
) else (
    echo [!] Failed to create scheduled task. Trying with current user...
    schtasks /Create ^
        /TN "%SERVICE_NAME%" ^
        /TR "\"%PYTHON_EXE%\" app.py" ^
        /SC ONLOGON ^
        /RL HIGHEST ^
        /F
)

:: Also create a restart-on-crash wrapper
echo [*] Creating watchdog script...
(
echo import subprocess, time, os, sys
echo os.chdir^(r"%APP_DIR%"^)
echo while True:
echo     print^(f"[Watchdog] Starting Expedite Strike at {time.strftime^('%%H:%%M:%%S'^)}"^)
echo     proc = subprocess.Popen^([r"%PYTHON_EXE%", "app.py"]^)
echo     proc.wait^(^)
echo     rc = proc.returncode
echo     print^(f"[Watchdog] Process exited with code {rc}"^)
echo     if os.path.exists^(os.path.join^(r"%APP_DIR%", ".stop_service"^)^):
echo         print^("[Watchdog] Stop file detected — shutting down"^)
echo         break
echo     print^("[Watchdog] Restarting in 5 seconds..."^)
echo     time.sleep^(5^)
) > "%APP_DIR%\service_watchdog.py"

:: Update the task to use the watchdog
schtasks /Change ^
    /TN "%SERVICE_NAME%" ^
    /TR "\"%PYTHON_EXE%\" \"%APP_DIR%\service_watchdog.py\"" ^
    /F >nul 2>&1

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  INSTALLATION COMPLETE                              ║
echo  ║                                                     ║
echo  ║  Expedite Strike will now:                          ║
echo  ║    √ Start on system boot automatically             ║
echo  ║    √ Keep running after logout                      ║
echo  ║    √ Auto-restart if it crashes                     ║
echo  ║    √ Survive screensaver and sleep                  ║
echo  ║                                                     ║
echo  ║  To start NOW:                                      ║
echo  ║    schtasks /Run /TN "ExpediteStrike"               ║
echo  ║                                                     ║
echo  ║  To stop:                                           ║
echo  ║    schtasks /End /TN "ExpediteStrike"               ║
echo  ║                                                     ║
echo  ║  To uninstall:                                      ║
echo  ║    schtasks /Delete /TN "ExpediteStrike" /F         ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
pause
