import argparse, concurrent.futures, errno, html, json, socket, sys, time
from datetime import datetime, timezone
VERSION = "1.1.0"
SERVICES = {21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",139:"NETBIOS-SSN",143:"IMAP",443:"HTTPS",445:"SMB",587:"SMTP-SUBMISSION",993:"IMAPS",995:"POP3S",3306:"MYSQL",3389:"RDP",5432:"POSTGRESQL",5900:"VNC",6379:"REDIS",8080:"HTTP-ALT",8443:"HTTPS-ALT",27017:"MONGODB"}
def parse_ports(spec):
    ports=set()
    for part in spec.split(","):
        part=part.strip()
        if not part: continue
        if "-" in part:
            a,b=map(int,part.split("-",1))
            if a>b: raise ValueError("Range start must be <= end")
            if b-a>65534: raise ValueError("Port range too large")
            ports.update(range(a,b+1))
        else: ports.add(int(part))
    if not ports or min(ports)<1 or max(ports)>65535: raise ValueError("Ports must be 1..65535")
    return sorted(ports)
def scan(ip, port, timeout, show_all):
    start=time.monotonic()
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout); code=s.connect_ex((ip,port))
        ms=round((time.monotonic()-start)*1000,2)
        if code==0: state="open"
        elif code==errno.ECONNREFUSED: state="closed"
        elif code in (errno.ETIMEDOUT,errno.EHOSTUNREACH,errno.ENETUNREACH,errno.EACCES,errno.EPERM): state="filtered"
        else: state="unknown"
        if state!="open" and not show_all: return None
        try: service=socket.getservbyport(port,"tcp").upper()
        except OSError: service=SERVICES.get(port,"UNKNOWN")
        return {"port":port,"protocol":"tcp","state":state,"service":service if state=="open" else "-","response_ms":ms}
    except OSError as e:
        return {"port":port,"protocol":"tcp","state":"unknown","service":"-","error":str(e)} if show_all else None
def main():
    p=argparse.ArgumentParser(prog="anas-ports",description="ANAS PORTS PRO v1.1.0 — authorized TCP scanning")
    p.add_argument("target",help="Hostname or IPv4 address")
    p.add_argument("-p","--ports",default="1-1024",help='Ports/ranges, e.g. "22,80,443" or "1-1024"')
    p.add_argument("-t","--timeout",type=float,default=.5,help="Timeout 0.05..10 seconds")
    p.add_argument("-w","--workers",type=int,default=100,help="Concurrent connections 1..200")
    p.add_argument("--show-closed",action="store_true",help="Include closed/filtered/unknown ports")
    p.add_argument("-o","--output",help="Save JSON report")
    p.add_argument("--html",help="Save HTML report")
    a=p.parse_args()
    if not .05<=a.timeout<=10: p.error("--timeout must be between 0.05 and 10")
    if not 1<=a.workers<=200: p.error("--workers must be between 1 and 200")
    try: ports=parse_ports(a.ports); ip=socket.gethostbyname(a.target)
    except (ValueError,socket.gaierror) as e: p.error(str(e))
    print(f"ANAS PORTS PRO v{VERSION} | Developer: Anas Khshan")
    print(f"Target: {a.target} | Ports: {len(ports)}")
    print("Use only on systems you own or are authorized to test.")
    start=time.monotonic(); results=[]; done=0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
            futures=[pool.submit(scan,ip,port,a.timeout,a.show_closed) for port in ports]
            for f in concurrent.futures.as_completed(futures):
                done+=1; item=f.result()
                if item:
                    results.append(item)
                    if item["state"]=="open": print(f'[OPEN] {item["port"]}/tcp {item["service"]} ({item["response_ms"]} ms)')
                if done==len(ports) or done%max(1,len(ports)//20)==0:
                    print(f"\rProgress: {done*100//len(ports)}% ({done}/{len(ports)})",end="",flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted."); return 130
    results.sort(key=lambda x:x["port"]); elapsed=round(time.monotonic()-start,2)
    report={"tool":"ANAS PORTS PRO","version":VERSION,"developer":"Anas Khshan","target":a.target,"resolved_ip":ip,"timestamp_utc":datetime.now(timezone.utc).isoformat(),"elapsed_seconds":elapsed,"open_ports":sum(x["state"]=="open" for x in results),"results":results}
    print(f"\nCompleted in {elapsed}s | Open TCP ports: {report['open_ports']}")
    if a.output:
        with open(a.output,"w",encoding="utf-8") as f: json.dump(report,f,indent=2,ensure_ascii=False)
        print("JSON report saved:",a.output)
    if a.html:
        rows="".join("<tr>"+"".join(f"<td>{html.escape(str(r.get(k,'')))}</td>" for k in ("port","protocol","state","service","response_ms"))+"</tr>" for r in results)
        page="<!doctype html><meta charset='utf-8'><title>ANAS PORTS PRO report</title><h1>ANAS PORTS PRO v1.1.0</h1><p>Developer: Anas Khshan</p><p>Authorized testing only. Open port does not prove a vulnerability.</p><table border='1'><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Response ms</th></tr>"+rows+"</table>"
        with open(a.html,"w",encoding="utf-8") as f:f.write(page)
        print("HTML report saved:",a.html)
    print("Note: closed/filtered labels are best-effort; firewalls can affect results.")
    return 0
if __name__=="__main__": raise SystemExit(main())
