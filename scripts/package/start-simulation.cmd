@echo off
rem Starts Proculus on an emulated network: scans find made-up hosts and web servers, nothing is sent anywhere.
rem Needs no nmap. Uses its own data directory (data-sim). UI: http://127.0.0.1:8080/
cd /d "%~dp0"
if not exist data-sim mkdir data-sim
if "%~1"=="" start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8080/"
proculus.exe serve --simulate --store data-sim %*
