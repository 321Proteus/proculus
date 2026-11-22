#!/bin/sh
# Starts Proculus on an emulated network: scans find made-up hosts and web servers, nothing is sent anywhere.
# Needs no nmap. Uses its own data directory (data-sim). UI: http://127.0.0.1:8080/
cd "$(dirname "$0")" || exit 1
mkdir -p data-sim
if [ $# -eq 0 ]; then
	( sleep 2; if command -v open >/dev/null 2>&1; then open http://127.0.0.1:8080/; elif command -v xdg-open >/dev/null 2>&1; then xdg-open http://127.0.0.1:8080/; fi ) >/dev/null 2>&1 &
fi
exec ./proculus serve --simulate --store data-sim "$@"
