@echo off
title Aegis 24/7 Fleet Watchdog
cd /d " %~dp0\
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
echo ==========================================================
echo Starting Aegis 24/7 High-Availability Fleet Watchdog...
echo This watchdog checks ports 9000-9021 every 8 seconds and
echo automatically revives any service that goes offline.
echo ==========================================================
python fleet_watchdog.py
pause
