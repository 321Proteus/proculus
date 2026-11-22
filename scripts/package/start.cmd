@echo off
rem Starts Proculus: the API on port 8081 and the web UI on http://127.0.0.1:8080/
rem Options after the script name are passed on (the last one wins), e.g. start.cmd --ui-port 9000
cd /d "%~dp0"
if not exist data mkdir data
where nmap >nul 2>nul || echo note: nmap was not found; real scans need it ^(see README.txt^). The simulation works without it: start-simulation.cmd
if "%~1"=="" start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8080/"
proculus.exe serve --store data --scan-ceiling 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 %*
