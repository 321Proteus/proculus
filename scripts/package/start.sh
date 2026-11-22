#!/bin/sh
# Starts Proculus: the API on port 8081 and the web UI on http://127.0.0.1:8080/
# Options after the script name are passed on (the last one wins), e.g. ./start.sh --ui-port 9000 --port 9001
cd "$(dirname "$0")" || exit 1
mkdir -p data
if ! command -v nmap >/dev/null 2>&1; then
	echo "note: nmap was not found; real scans need it (see README.txt). The simulation works without it: ./start-simulation.sh"
fi
if [ $# -eq 0 ]; then # open the browser once the server is up (only with the default port)
	( sleep 2; if command -v open >/dev/null 2>&1; then open http://127.0.0.1:8080/; elif command -v xdg-open >/dev/null 2>&1; then xdg-open http://127.0.0.1:8080/; fi ) >/dev/null 2>&1 &
fi
exec ./proculus serve --store data --scan-ceiling 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 "$@"
