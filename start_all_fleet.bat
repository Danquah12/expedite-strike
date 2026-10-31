@echo off
title Aegis Windows Full Fleet Launcher
echo ====================================================================
echo        Starting Aegis Windows Fleet & SOC Microservices
echo ====================================================================

cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

echo [*] Starting Port 9000 (launchpad_server.py - Mission Control)...
start /B "" python launchpad_server.py --port 9000

echo [*] Starting Port 9011 (app.py - Aegis SOC & Autonomous PenTest)...
start /B "" python app.py

echo [*] Starting Port 9012 (external_assessment_app.py - Expedite Strike & Fusion)...
start /B "" python external_assessment_app.py --port 9012

echo [*] Starting Port 9013 (red_team_app.py - Red Team Ops & Exploitability)...
start /B "" python red_team_app.py --port 9013

echo [*] Starting Port 9014 (red_team_suite_app.py - Cloud Pentest & IAM PrivEsc)...
start /B "" python red_team_suite_app.py --port 9014

echo [*] Starting Port 9015 (defence_app.py - Cyber Defence & AXIOM DAST)...
start /B "" python defence_app.py --port 9015

echo [*] Starting Port 9016 (specialised_app.py - Specialised Ops & Ransomware Recovery)...
start /B "" python specialised_app.py --port 9016

echo [*] Starting Port 9017 (grc_app.py - Unified Integration & SOAR)...
start /B "" python grc_app.py --port 9017

echo [*] Starting Port 9018 (dfir_app.py - CERBERUS-RE DFIR & Malware Intel)...
start /B "" python dfir_app.py --port 9018

echo [*] Starting Port 9019 (platform_app.py - Platform Infrastructure & Assets)...
start /B "" python platform_app.py --port 9019

echo [*] Starting Port 9020 (pentest_console.py - Autonomous PenTest Console)...
start /B "" python pentest_console.py --port 9020

echo [*] Starting Port 9021 (reports_app.py - Reporting & Compliance Suite)...
start /B "" python reports_app.py --port 9021

echo ====================================================================
echo [+] All Fleet services started!
echo     - Mission Control:     http://localhost:9000
echo     - Aegis SOC Platform:  http://localhost:9011/app/
echo     - Autonomous PenTest: http://localhost:9011/app/?standalone=1
echo     - Expedite Strike:     http://localhost:9012
echo     - Red Team Ops:        http://localhost:9013
echo     - Cloud Pentest:       http://localhost:9014
echo     - Cyber Defence:       http://localhost:9015
echo     - Ransomware Recovery: http://localhost:9016
echo     - Unified SOAR/GRC:    http://localhost:9017
echo     - CERBERUS-RE DFIR:    http://localhost:9018
echo     - Platform Infra:      http://localhost:9019
echo     - PenTest Console:     http://localhost:9020
echo     - Reporting Suite:     http://localhost:9021
echo     - Cloud Launchpad:     https://ecosystem-launchpad.vercel.app
echo ====================================================================
pause
