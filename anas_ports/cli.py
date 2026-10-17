#!/usr/bin/env python3
"""ANAS PORTS PRO - TCP port scanner for systems you own or are authorized to test."""
import argparse
import concurrent.futures
import json
import socket
import sys
import time
from datetime import datetime, timezone

BANNER = r"""
╔══════════════════════════════════════════════════╗
║                 ANAS PORTS PRO                  ║
║          Authorized Network Port Scanner        ║
║               Developer: Anas Khshan            ║
╚══════════════════════════════════════════════════╝
"""

COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    111: "RPCBIND", 123: "NTP", 135: "MS-RPC", 139: "NETBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-SUBMISSION", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "ORACLE",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC",
    6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB",
}

def parse_ports(spec):
    """Parse comma-separated ports and ranges, e.g. 22,80,443,8000-8010."""
    result = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            pieces = part.split("-", 1)
            if len(pieces) != 2:
                raise ValueError(f"Invalid port range: {part}")
            start, end = (int(pieces[0]), int(pieces[1]))
            if start > end:
                raise ValueError(f"Range start exceeds end: {part}")
            if end - start > 65534:
                raise ValueError("Port range is too large.")
            result.update(range(start, end + 1))
        else:
            result.add(int(part))
    if not result or any(p < 1 or p > 65535 for p in result):
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(result)

def scan_one(host, port, timeout):
    """Attempt a TCP connection; return a record only when the port accepts it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            if code == 0:
                try:
                    service = socket.getservbyport(port, "tcp").upper()
                except OSError:
                    service = COMMON_SERVICES.get(port, "UNKNOWN")
                return {"port": port, "protocol": "tcp", "state": "open", "service": service}
    except (OSError, OverflowError):
        return None
    return None

def main():
    parser = argparse.ArgumentParser(
        prog="anas-ports",
        description="Scan TCP ports on a host you own or are authorized to test."
    )
    parser.add_argument("target", help="Hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help='Ports, e.g. "22,80,443" or "1-1024" (default: 1-1024)')
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Connection timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Maximum concurrent connections (default: 100, max: 200)")
    parser.add_argument("-o", "--output", help="Save results as JSON to this file")
    args = parser.parse_args()

    if not 0.05 <= args.timeout <= 10:
        parser.error("--timeout must be between 0.05 and 10 seconds")
    if not 1 <= args.workers <= 200:
        parser.error("--workers must be between 1 and 200")

    try:
        ports = parse_ports(args.ports)
        target_ip = socket.gethostbyname(args.target)
    except (ValueError, socket.gaierror) as exc:
        parser.error(str(exc))

    print(BANNER)
    print(f"[+] Target: {args.target} ({target_ip})")
    print(f"[+] TCP ports to check: {len(ports)}")
    print("[!] Use only on systems you own or have explicit permission to test.\n")

    started = time.monotonic()
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            jobs = {pool.submit(scan_one, target_ip, port, args.timeout): port for port in ports}
            completed = 0
            for future in concurrent.futures.as_completed(jobs):
                completed += 1
                record = future.result()
                if record:
                    results.append(record)
                    print(f"[OPEN] {record['port']}/tcp  - {record['service']}")
                if completed % max(1, len(ports) // 20) == 0 or completed == len(ports):
                    pct = int(completed * 100 / len(ports))
                    print(f"\r[*] Progress: {pct}% ({completed}/{len(ports)})", end="", flush=True)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return 130

    results.sort(key=lambda item: item["port"])
    elapsed = round(time.monotonic() - started, 2)
    print(f"\n\n[+] Scan completed in {elapsed}s")
    print(f"[+] Open TCP ports: {len(results)}")

    if args.output:
        report = {
            "tool": "ANAS PORTS PRO",
            "version": "1.0.0",
            "developer": "Anas Khshan",
            "target": args.target,
            "resolved_ip": target_ip,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "results": results,
        }
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, ensure_ascii=False)
            print(f"[+] JSON report saved to: {args.output}")
        except OSError as exc:
            print(f"[!] Could not save report: {exc}", file=sys.stderr)
            return 1
    print("[i] Open ports do not automatically mean a vulnerability exists.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
