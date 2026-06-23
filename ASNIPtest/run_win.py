#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest Windows Command Line Version
Usage: python run_win.py AS209242 [AS3214 ...]
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re, argparse
from pathlib import Path
from datetime import datetime

def detect_hardware():
    cpu = multiprocessing.cpu_count()
    ram_mb = 512
    try:
        import ctypes
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        ram_mb = stat.ullAvailPhys // (1024 * 1024)
    except:
        pass
    return cpu, ram_mb

def get_public_ip():
    apis = [
        "https://api.ipify.org",
        "https://api-ipv4.ip.sb/ip",
        "https://ifconfig.me/ip",
    ]
    for url in apis:
        try:
            return urllib.request.urlopen(url, timeout=5).read().decode("utf-8").strip()
        except:
            continue
    return "127.0.0.1"

CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE = min(CPU_CORES * 1000, 16000)
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT = 64

print(f"Hardware: {CPU_CORES} cores, {RAM_MB}MB RAM")
print(f"Recommended rate: {MASSCAN_RATE} pps, cf-scanner concurrency: {CF_SCANNER_CONC}")

BASE = Path(__file__).parent
VERIFY_PY = BASE / "verify.py"
API_URL = "https://api.090227.xyz/check"
MASSCAN_EXE = BASE / "masscan.exe"
CF_SCANNER_EXE = BASE / "cf-scanner.exe"

def fetch_prefixes(asns):
    cidrs = []
    for asn in asns:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
                count = 0
                for p in data["data"]["prefixes"]:
                    if ":" not in p["prefix"]:
                        cidrs.append(p["prefix"])
                        count += 1
                print(f"AS{asn} -> {count} CIDRs")
        except Exception as e:
            print(f"AS{asn} -> Failed: {e}")
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"Total: {len(cidrs)} CIDRs")
    return cidrs

def run_masscan(ports="443,8443,2053,2083,2087,2096"):
    result_file = BASE / "masscan_result.txt"
    if not MASSCAN_EXE.exists():
        print("ERROR: masscan.exe not found")
        return 0
    
    cmd = [str(MASSCAN_EXE), "-iL", str(BASE / "cidrs.txt"), "-p", ports, "--rate", str(MASSCAN_RATE), "-oL", str(result_file), "--wait", "3"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    
    bar_width = 30
    last_pct = -1
    for line in proc.stderr:
        m = re.search(r"(\d+\.?\d*)%\s*done", line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
    
    lines = []
    if result_file.exists():
        with open(result_file) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "open":
                    lines.append(f"{parts[3]}:{parts[2]}")
    result_file.write_text("\n".join(lines) + "\n")
    print(f"Open ports: {len(lines)}")
    return len(lines)

def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"
    if not CF_SCANNER_EXE.exists():
        print("ERROR: cf-scanner.exe not found")
        return 0
    if new_file.stat().st_size == 0:
        print("No open ports, skipping")
        return 0
    cmd = [str(CF_SCANNER_EXE), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    bar_width = 30
    last_pct = -1
    for line in proc.stdout:
        m = re.search(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)", line)
        if m:
            pct = min(float(m.group(2)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
    hits = sum(1 for _ in open(hits_file)) if hits_file.exists() else 0
    print(f"CF nodes: {hits}")
    return hits

def api_verify(mode="tls", api_url=API_URL):
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"
    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("No CF nodes, skipping")
        return 0
    cmd = [sys.executable, str(VERIFY_PY), "--input", str(hits_file), "--output", str(verified_file), "--mode", mode, "--concurrent", str(API_CONCURRENT), "--fallback"]
    if mode == "api":
        cmd.extend(["--api", api_url])
    subprocess.run(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
    passed = sum(1 for _ in open(verified_file)) - 1 if verified_file.exists() else 0
    print(f"Verification passed: {passed}")
    return passed

def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("No results")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"output_{asn_tag}_{ts}.csv"
    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP地址"):
                continue
            if line.count(",") >= 8:
                lines.append(line)
    with open(output, "w", encoding="utf-8-sig") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for line in lines:
            f.write(line + "\n")
    print(f"Result: {len(lines)} nodes -> {output.name}")

def main():
    parser = argparse.ArgumentParser(description="ASNIPtest Windows CLI")
    parser.add_argument("asns", nargs="+", help="ASN numbers (e.g., AS209242)")
    parser.add_argument("--ports", default="443,8443,2053,2083,2087,2096", help="Ports to scan")
    parser.add_argument("--mode", choices=["tls", "api"], default="tls", help="Verification mode")
    parser.add_argument("--api", default=API_URL, help="API URL for remote verification")
    args = parser.parse_args()
    
    asns = [a.replace("AS", "").replace("as", "") for a in args.asns]
    print(f"\nScanning ASN: {', '.join('AS' + a for a in asns)}")
    print("-" * 50)
    
    print("\n[Step 1/4] Fetching CIDRs...")
    fetch_prefixes(asns)
    
    print("\n[Step 2/4] Port scanning...")
    if run_masscan(args.ports) == 0:
        return
    
    print("\n[Step 3/4] CF node detection...")
    if cf_scan() == 0:
        return
    
    print(f"\n[Step 4/4] Verification ({args.mode})...")
    api_verify(args.mode, args.api)
    
    print("\n" + "=" * 50)
    output_csv(asns)
    print("Done!")

if __name__ == "__main__":
    main()