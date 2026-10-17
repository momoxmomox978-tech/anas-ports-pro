# ANAS PORTS PRO

**Developer:** Anas Khshan  
**Version:** 1.0.0  
**License:** MIT

ANAS PORTS PRO is a lightweight Python TCP port scanner for **authorized security testing**. It checks selected TCP ports, reports ports that accept connections, maps common ports to service names, and can save a JSON report.

> **Permission required:** Only scan devices and networks you own or have explicit permission to test. This tool does not exploit vulnerabilities, bypass authentication, or guarantee that a service is vulnerable.

## Features

- TCP port scanning with bounded concurrency
- Scan selected ports, comma-separated lists, or ranges
- Live progress and open-port output
- Common service-name identification
- JSON report export
- Python standard library only; no third-party dependencies

## Requirements

- Python 3.9 or newer
- Linux, macOS, or Windows

## Install on Kali Linux / Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv git
git clone https://github.com/YOUR-USERNAME/anas-ports-pro.git
cd anas-ports-pro
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

After installation, run:

```bash
anas-ports --help
```

Replace `YOUR-USERNAME` with your GitHub username and use the exact repository name you create.

### Install directly from a cloned folder (without packaging)

```bash
python3 -m anas_ports.cli --help
```

## Usage

Scan the default TCP ports 1–1024 on an authorized target:

```bash
anas-ports 192.168.1.10
```

Scan selected ports:

```bash
anas-ports 192.168.1.10 -p 22,80,443
```

Scan a range and save JSON:

```bash
anas-ports 192.168.1.10 -p 1-2000 --timeout 0.5 --workers 100 -o report.json
```

Use a hostname you are authorized to test:

```bash
anas-ports example.internal -p 22,80,443
```

## Options

| Option | Meaning |
| --- | --- |
| `-p`, `--ports` | Ports, list, or range (default `1-1024`) |
| `-t`, `--timeout` | Per-connection timeout, 0.05–10 seconds |
| `-w`, `--workers` | Concurrent connections, 1–200 |
| `-o`, `--output` | JSON report output path |
| `-h`, `--help` | Show help |

## Safety and limitations

- TCP only; UDP scanning is not implemented.
- A filtered port may appear closed or not appear in results.
- Service names are best-effort labels based on port numbers, not verified service fingerprints.
- A port being open is not proof of a vulnerability.
- No exploitation or credential attacks are included.

## Copyright

Copyright (c) 2026 Anas Khshan.  
This project is provided under the MIT License. See `LICENSE`.

If you fork or redistribute this project, retain the copyright and license notice.
