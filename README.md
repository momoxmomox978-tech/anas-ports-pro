# ANAS PORTS PRO v1.1.0
**Developer:** Anas Khshan | **License:** MIT

A lightweight TCP connect scanner for authorized testing. v1.1 adds response-time measurements, improved best-effort state labels, `--show-closed`, and JSON/HTML reports.

## Install on Kali Linux
```bash
sudo apt update
sudo apt install -y git python3 python3-venv pipx
git clone https://github.com/YOUR-USERNAME/anas-ports-pro.git
cd anas-ports-pro
pipx install .
```
Update an existing pipx installation from this folder with `pipx install --force .`.

## Examples
```bash
anas-ports --help
anas-ports 127.0.0.1 -p 22,80,443
anas-ports 127.0.0.1 -p 1-1024 -o report.json --html report.html
anas-ports 127.0.0.1 -p 1-100 --show-closed
```
Only scan devices/networks you own or have explicit permission to test. This is not a full Nmap replacement; it does not scan UDP, fingerprint operating systems, exploit vulnerabilities, or reliably identify service versions. Open ports are not proof of vulnerabilities.
