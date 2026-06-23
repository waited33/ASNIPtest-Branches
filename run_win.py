#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest Windows 版本
从 ASN 编号出发，自动完成 IP 段拉取 → 端口扫描 → Cloudflare 反代节点检测
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re
from pathlib import Path
from datetime import datetime

# Windows 兼容检测硬件
def detect_hardware():
    cpu = multiprocessing.cpu_count()
    try:
        import ctypes
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        mem_mb = stat.ullAvailPhys // (1024 * 1024)
    except:
        mem_mb = 512
    return cpu, mem_mb

# 简化的速率探测 (Windows)
def probe_masscan_rate():
    cores = multiprocessing.cpu_count()
    return max(1000, min(cores * 1000, 16000))

CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE    = probe_masscan_rate()
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT  = min(CPU_CORES * 16, 32)
API_CHUNK       = 2000 if RAM_MB < 1024 else 5000

print(f"  硬件: {CPU_CORES}核 {RAM_MB}MB → masscan {MASSCAN_RATE}pps cf-scanner {CF_SCANNER_CONC}c API {API_CONCURRENT}c")

# 获取公网 IP
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

# 获取局域网 IP
def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "127.0.0.1"

# 公网 IP + 运营商检测
def detect_isp():
    ip = get_public_ip()
    print(f"\n  本机公网 IP: {ip}")
    if ip == "127.0.0.1":
        print("  (无法获取公网 IP，请检查网络连接)")
        return ip, "", ""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            country = data.get("country", "")
            org = data.get("org", "")
            city = data.get("city", "")
            if country == "CN":
                isp = org.split(" ", 1)[-1] if org else "未知"
                print(f"  地区: {city}, {country}  🇨🇳  运营商: {isp}")
            else:
                isp = org
                print(f"  地区: {city}, {country}  机构: {org}")
            return ip, country, isp
    except Exception as e:
        print(f"  (无法获取详情: {e})")
    return ip, "", ""

GLOBAL_IP, GLOBAL_COUNTRY, GLOBAL_ISP = detect_isp()

BASE      = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner.exe"
VERIFY_PY  = BASE / "verify.py"
API_URL    = "https://api.090227.xyz/check"

# Step 1: ASN → CIDR
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
                print(f"  AS{asn} → {count} 个 IPv4 CIDR")
        except Exception as e:
            print(f"  AS{asn} → 失败: {e}")
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  共 {len(cidrs)} 个 CIDR")
    return cidrs

# 端口解析
with open(BASE / "ports.txt") as f:
    _default_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
DEFAULT_PORTS = ",".join(_default_ports)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                a, b = part.split('-', 1)
                pa, pb = int(a), int(b)
                if pa < 1 or pb > 65535 or pa > pb:
                    continue
                ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else ""

def run_masscan(ports_str=None):
    ports = ports_str if ports_str else DEFAULT_PORTS
    if not ports or ports == ",":
        ports = DEFAULT_PORTS
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

    if result_file.exists():
        result_file.unlink()

    masscan_path = BASE / "masscan.exe"
    if not masscan_path.exists():
        print("  ❌ masscan.exe 未找到，请确保已安装 masscan Windows 版本")
        print("     下载地址: https://github.com/robertdavidgraham/masscan/releases")
        raise FileNotFoundError("masscan.exe not found")

    cmd = [
        str(masscan_path), "-iL", str(ip_file),
        "-p", ports,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--wait", "5"
    ]
    
    print(f"  执行: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    bar_width = 30
    last_pct = -1
    stderr_lines = []
    for line in proc.stderr:
        stderr_lines.append(line)
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
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        stderr_text = "".join(stderr_lines)
        print(f"  ❌ masscan 执行失败: {stderr_text}")
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    lines = []
    with open(result_file) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "open":
                lines.append(f"{parts[3]}:{parts[2]}")
    result_file.write_text("\n".join(lines) + "\n")
    print(f"  开放端口: {len(lines)}")
    return len(lines)

# Step 4: cf-scanner 粗筛
def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if new_file.stat().st_size == 0:
        print("  无开放端口，跳过")
        return 0

    if not os.access(CF_SCANNER, os.X_OK):
        os.chmod(CF_SCANNER, 0o755)

    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
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
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    hits = sum(1 for _ in open(hits_file))
    print(f"  CF 节点: {hits}")
    return hits

# Step 5: 精筛 (使用本地 TLS 验证)
def api_verify():
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF 节点，跳过")
        return 0

    print("  使用本地 TLS 验证模式")
    subprocess.run([
        sys.executable, str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--mode", "tls",
        "--chunk", str(API_CHUNK),
        "--concurrent", str(API_CONCURRENT * 2),
        "--fallback"
    ], check=True)
    
    if verified_file.exists():
        passed = sum(1 for _ in open(verified_file)) - 1  # 减去表头
    else:
        passed = 0
    print(f"  精筛通过: {passed}")
    return passed

# Step 6: 测速
def speed_test():
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点，跳过")
        return

    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("IP地址"):
                lines.append(line)
                continue
            lines.append(line)

    if len(lines) <= 1:
        print("  无节点，跳过")
        return

    header = lines[0]
    entries = lines[1:]
    total = len(entries)
    tested = 0

    print(f"  节点数: {total}")

    with open(verified_file, "w") as f:
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

            speed_mbps = 0
            if latency > 0:
                try:
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp:
                        tmp_path = tmp.name
                    
                    r = subprocess.run([
                        "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
                        "-o", tmp_path, "-s", "-w", "%{speed_download}",
                        "--connect-timeout", "5", "--max-time", "20",
                        "https://speed.cloudflare.com/__down?bytes=10485760"
                    ], capture_output=True, text=True, timeout=25)
                    os.remove(tmp_path)
                    speed_bps = float(r.stdout.strip() or 0)
                    speed_mbps = round(speed_bps * 8 / 1000000, 2)
                except:
                    pass

            parts[6] = str(latency)
            parts[7] = str(speed_mbps)
            f.write(",".join(parts) + "\n")

            tested += 1
            pct = tested / total * 100
            bar_width = 30
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)
            sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | 延迟 {latency}ms  {speed_mbps}Mbps  {'':20}")
            sys.stderr.flush()

    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | 测速完成: {total} 个节点{'':20}\n")

# 输出 + 下载链接
def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无结果")
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

    print(f"\n  结果: {len(lines)} 条 → {output.name}")

    try:
        lan_ip = get_lan_ip()
        port = 8899
        print(f"\n  📥 下载链接 (临时, 按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{output.name}  (本机)")
        public_ip = get_public_ip()
        if public_ip != "127.0.0.1" and public_ip != lan_ip:
            print(f"  http://{public_ip}:{port}/{output.name}  (公网)")
        print()
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
        server.terminate()
        server.wait()
    except:
        pass

# Main
if __name__ == "__main__":
    if len(sys.argv) < 2:
        try:
            raw = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  请在终端运行: cd {BASE} && {sys.executable} run_win.py\n")
            sys.exit(0)
        if not raw:
            print(f"用法: {sys.executable} run_win.py AS209242 或 {sys.executable} run_win.py AS209242,AS3214")
            sys.exit(1)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        args = sys.argv[1:]
        i = 0
        asn_args = []
        while i < len(args):
            if args[i] == "-p":
                i += 2
            else:
                asn_args.append(args[i])
                i += 1
        raw = ",".join(asn_args)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
        if not asns:
            print(f"用法: {sys.executable} run_win.py AS209242 或 {sys.executable} run_win.py AS209242 -p 8443")
            sys.exit(1)
    print(f"\n  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    scan_ports = DEFAULT_PORTS
    if len(sys.argv) < 2:
        print(f"  默认端口: {DEFAULT_PORTS}")
        try:
            port_input = input("  回车使用默认，或输入自定义端口 (如 80 或 1-1000 或 80,443,8000-9000): ").strip()
        except (EOFError, KeyboardInterrupt):
            port_input = ""
        if port_input:
            parsed = parse_ports(port_input)
            if parsed:
                scan_ports = parsed
                print(f"  扫描端口: {scan_ports}")
    else:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "-p" and i < len(sys.argv) - 1:
                scan_ports = parse_ports(sys.argv[i+1])
                print(f"  自定义端口: {scan_ports}")
                break

    steps = [
        ("1/6 ASN→CIDR", lambda: fetch_prefixes(asns)),
        ("2/6 masscan",   lambda: run_masscan(scan_ports)),
        ("3/6 cf-scanner", cf_scan),
        ("4/6 API精筛",   api_verify),
    ]

    choice = ""
    try:
        choice = input("\n  是否测速？(y/n，默认跳过): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        pass
    if choice == "y":
        steps.append(("6/6 测速", speed_test))
    else:
        print("  跳过测速\n")

    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  ❌ 失败: {e}")
            sys.exit(1)

    output_csv(asns)
    print("\n✓ 完成\n")
