PROCULUS - attack surface scanner (AGH CBI hackathon prototype)
================================================================

Start (no installation, no dependencies):

  macOS / Linux:   ./start.sh                 (real scans; needs nmap)
                   ./start-simulation.sh      (emulated network; needs nothing)
  Windows:         start.cmd   /   start-simulation.cmd

Then open http://127.0.0.1:8080/ (the scripts open it for you).

First run: the terminal prints a SETUP TOKEN. Paste it into the browser to create the
administrator account. Then, for real scans: Admin > Scanning (turn scans on, set the address
scope and ports). In simulation mode scans are already on and can only touch the emulated network.

Real scans need nmap on the PATH (https://nmap.org/download):
  macOS: brew install nmap     Debian/Ubuntu: sudo apt install nmap     Windows: install from nmap.org

Ports: API 8081, UI 8080. If one is taken the program stops with "cannot listen on ...";
choose others:  ./start.sh --port 9001 --ui-port 9000

Data is kept in ./data (real) and ./data-sim (simulation). Delete the directory for a fresh start.
./proculus reset --store data --runs --yes    does the same and keeps everything else.
./proculus serve --help                       lists every option.

macOS: if the system refuses to open the program ("cannot verify the developer"), run once:
  xattr -dr com.apple.quarantine .

Contents:  proculus (the program, UI included)   examples/ (scan settings and a custom signature)
           start*.sh / start*.cmd (launchers)    README.txt (this file)
Only scan networks you are allowed to scan.
