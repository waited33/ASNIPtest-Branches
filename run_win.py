#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest Windows 版 - 从 ASN 拉取 IP，masscan 扫描，检测 Cloudflare 反代节点
支持智能速率探测、TLS 本地验证、GUI 界面
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).parent.resolve()
MASSCAN_EXE = BASE / "masscan.exe"
CF_SCANNER_EXE = BASE / "cf-scanner.exe"
VERIFY_PY = BASE / "verify.py"
PORTS_FILE = BASE / "ports.txt"
API_URL = "https://api.090227.xyz/check"

IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    CREATE_NO_WINDOW = 0x08000000
else:
    CREATE_NO_WINDOW = 0

def detect_hardware():
    cpu = multiprocessing.cpu_count()
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_uint32),
                        ("dwMemoryLoad", ctypes.c_uint32),
                        ("ullTotalPhys", ctypes.c_uint64),
                        ("ullAvailPhys", ctypes.c_uint64),
                        ("ullTotalPageFile", ctypes.c_uint64),
                        ("ullAvailPageFile", ctypes.c_uint64),
                        ("ullTotalVirtual", ctypes.c_uint64),
                        ("ullAvailVirtual", ctypes.c_uint64),
                        ("ullAvailExtendedVirtual", ctypes.c_uint64)]
        ms = MEMORYSTATUSEX()
        ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
        mem_mb = ms.ullTotalPhys // (1024 * 1024)
    except:
        mem_mb = 2048
    return cpu, mem_mb

CPU_CORES, RAM_MB = detect_hardware()
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT = min(CPU_CORES * 16, 32)
API_CHUNK = 2000 if RAM_MB < 1024 else 5000

def get_public_ip():
    apis = [
        ("https://api.ipify.org", 5),
        ("https://api-ipv4.ip.sb/ip", 5),
        ("https://ifconfig.me/ip", 5),
        ("https://icanhazip.com", 5),
    ]
    for url, timeout in apis:
        try:
            return urllib.request.urlopen(url, timeout=timeout).read().decode("utf-8").strip()
        except Exception:
            continue
    return "127.0.0.1"

def probe_masscan_rate(target_ips=None):
    """智能速率探测 - 实测网卡发包上限"""
    if not MASSCAN_EXE.exists():
        return 5000
    probe_cidr = "104.16.0.0/28"
    probe_ports = "443"
    base_rate = 1000
    rate = base_rate
    try:
        for test_rate in [1000, 2000, 4000, 8000, 16000]:
            result_file = BASE / f"probe_{test_rate}.txt"
            cmd = [
                str(MASSCAN_EXE), probe_cidr,
                "-p", probe_ports,
                "--rate", str(test_rate),
                "-oL", str(result_file),
                "--wait", "0"
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
                if result_file.exists():
                    result_file.unlink()
                rate = test_rate
            except subprocess.TimeoutExpired:
                if result_file.exists():
                    result_file.unlink()
                break
            except Exception:
                if result_file.exists():
                    result_file.unlink()
                break
    except:
        pass
    return max(rate, 500)

MASSCAN_RATE = None

def log(msg, level="info"):
    print(msg, flush=True)

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
                log(f"  AS{asn} -> {count} 个 IPv4 CIDR")
        except Exception as e:
            log(f"  AS{asn} -> 失败: {e}")
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs), encoding="utf-8")
    log(f"  共 {len(cidrs)} 个 CIDR")
    return cidrs

def run_masscan(rate=None):
    global MASSCAN_RATE
    if rate is None:
        rate = MASSCAN_RATE
    ports = ",".join(line.strip() for line in open(PORTS_FILE, encoding="utf-8") if line.strip() and not line.startswith("#"))
    result_file = BASE / "masscan_result.txt"
    cidr_file = BASE / "cidrs.txt"

    cmd = [
        str(MASSCAN_EXE), "-iL", str(cidr_file),
        "-p", ports,
        "--rate", str(rate),
        "-oL", str(result_file),
        "--wait", "5"
    ]
    subprocess.run(cmd, check=True, creationflags=CREATE_NO_WINDOW)

    lines = []
    with open(result_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "open":
                lines.append(f"{parts[3]}:{parts[2]}")
    result_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"  开放端口: {len(lines)}")
    return len(lines)

def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if new_file.stat().st_size == 0:
        log("  无开放端口，跳过")
        return 0

    cmd = [str(CF_SCANNER_EXE), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)]
    subprocess.run(cmd, check=True, creationflags=CREATE_NO_WINDOW)
    hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace"))
    log(f"  CF 节点: {hits}")
    return hits

def api_verify(mode="api", api_url=API_URL, fallback=True):
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        log("  无 CF 节点，跳过")
        return 0

    cmd = [
        sys.executable, str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--api", api_url,
        "--mode", mode,
        "--chunk", str(API_CHUNK),
        "--concurrent", str(API_CONCURRENT),
    ]
    if fallback:
        cmd.append("--fallback")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", creationflags=CREATE_NO_WINDOW)
    for line in proc.stdout:
        line = line.strip()
        if line:
            log("  " + line)
    proc.wait()
    passed = sum(1 for _ in open(verified_file, encoding="utf-8", errors="replace")) - 1
    log(f"  精筛通过: {passed}")
    return passed

def speed_test(speed_url="https://speed.cloudflare.com/__down?bytes=524288"):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        log("  无节点，跳过")
        return

    lines = []
    with open(verified_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("IP"):
                lines.append(line)
                continue
            lines.append(line)

    if len(lines) <= 1:
        log("  无节点，跳过")
        return

    header = lines[0]
    entries = lines[1:]
    total = len(entries)
    tested = 0

    log(f"  节点数: {total}")

    with open(verified_file, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        for entry in entries:
            parts = entry.split(",")
            if len(parts) < 9:
                continue
            ip, port = parts[0], parts[1]

            latency = 0
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                t0 = time.time()
                s.connect((ip, int(port)))
                latency = round((time.time() - t0) * 1000)
                s.close()
            except:
                pass

            speed_kbps = 0
            if latency > 0:
                try:
                    r = subprocess.run([
                        "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
                        "-o", "NUL" if IS_WINDOWS else "/dev/null", "-s", "-w", "%{speed_download}",
                        "--connect-timeout", "5", "--max-time", "10",
                        speed_url
                    ], capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
                    speed_bps = float(r.stdout.strip() or 0)
                    speed_kbps = round(speed_bps / 1024)
                except:
                    pass

            parts[6] = str(latency)
            parts[7] = str(speed_kbps)
            f.write(",".join(parts) + "\n")

            tested += 1
            if tested % 10 == 0 or tested == total:
                log(f"  测速进度: {tested}/{total} | 延迟 {latency}ms  速度 {speed_kbps}KB/s")

    log(f"  测速完成: {total} 个节点")

def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        log("  无结果")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"result_{asn_tag}_{ts}.csv"

    lines = []
    with open(verified_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP"):
                continue
            if line.count(",") >= 8:
                lines.append(line)

    with open(output, "w", encoding="utf-8") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for line in lines:
            f.write(line + "\n")

    log(f"\n  结果: {len(lines)} 条 -> {output.name}")
    return output

def main():
    global MASSCAN_RATE

    asns_str = ""
    if len(sys.argv) >= 2:
        asns_str = " ".join(sys.argv[1:])
    else:
        try:
            asns_str = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
        except:
            pass

    if not asns_str:
        print("用法: python run_win.py AS209242 或 python run_win.py AS209242,AS3214")
        sys.exit(1)

    asns = [a.strip().replace("AS", "").replace("as", "") for a in asns_str.replace("，", ",").split(",") if a.strip()]
    print(f"\n  ASN: {', '.join(f'AS{a}' for a in asns)}")
    print(f"  硬件: {CPU_CORES}核 {RAM_MB}MB")

    print("\n  [步骤 1/5] 智能速率探测...")
    MASSCAN_RATE = probe_masscan_rate()
    print(f"  推荐速率: {MASSCAN_RATE} pps")

    print("\n  [步骤 2/5] ASN -> CIDR")
    fetch_prefixes(asns)

    print("\n  [步骤 3/5] masscan 端口扫描")
    run_masscan()

    print("\n  [步骤 4/5] cf-scanner 粗筛")
    cf_scan()

    print("\n  [步骤 5/5] API 精筛")
    api_verify()

    print("\n  [测速]")
    speed_test()

    output_csv(asns)
    print("\n完成")

if __name__ == "__main__":
    main()
