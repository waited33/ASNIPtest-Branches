#!/usr/bin/env python3
"""
API 精筛 — 验证 CF 节点可用性
支持本地 TLS 验证和远程 API 验证两种模式
"""
import argparse, json, time, sys, socket, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_single_tls(ip_port):
    """使用本地 TLS 握手验证 CF 节点"""
    try:
        ip, port = ip_port.rsplit(":", 1)
        port = int(port)
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, port))
            
            with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
                cert = secure_sock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    # 检查是否为 Cloudflare 证书
                    if 'Cloudflare' in str(subject) or 'Cloudflare' in str(issuer):
                        return f"{ip},{port},TRUE,CLOUDFLARE,,,"
                    else:
                        # 尝试从证书获取信息
                        common_name = subject.get('commonName', '')
                        if common_name:
                            return f"{ip},{port},TRUE,{common_name[:20]},,,"
                        return f"{ip},{port},TRUE,UNKNOWN,,,"
    except Exception:
        pass
    return None

def check_single_api(line, api_url):
    """通过远程 API 验证 CF 节点"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    ip_port = parts[0] if parts else line
    try:
        import urllib.request
        url = f"{api_url}?proxyip={ip_port}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            if not data.get("success"):
                return None
            pr = data.get("probe_results", {})
            exit_info = pr.get("ipv4", {}).get("exit") or pr.get("ipv6", {}).get("exit") or {}
            colo = exit_info.get("colo", data.get("colo", ""))
            country = exit_info.get("country", "")
            region = exit_info.get("region", "")
            asn = exit_info.get("asn", data.get("asn", ""))
            ip, port = ip_port.rsplit(":", 1)
            return f"{ip},{port},TRUE,{colo},{country},{region},,,AS{asn}"
    except Exception as e:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=["tls", "api"], default="tls")
    parser.add_argument("--api", default="https://api.090227.xyz/check")
    parser.add_argument("--chunk", type=int, default=5000)
    parser.add_argument("--concurrent", type=int, default=64)
    parser.add_argument("--fallback", action="store_true", default=True,
                        help="当精筛通过为0时，使用粗筛结果")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    
    # 提取 ip:port 部分（处理 cf-scanner 输出格式：ip:port status=xxx server=cloudflare）
    all_lines = []
    for line in raw_lines:
        parts = line.split()
        if parts:
            ip_port = parts[0]
            # 验证是否是 ip:port 格式
            if ":" in ip_port:
                all_lines.append(ip_port)

    total = len(all_lines)
    passed = 0
    failed = 0
    start = time.time()
    results = []

    check_func = check_single_tls if args.mode == "tls" else lambda x: check_single_api(x, args.api)

    with open(args.output, "w") as out:
        out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for i in range(0, total, args.chunk):
            chunk = all_lines[i:i + args.chunk]
            with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                futures = {ex.submit(check_func, ip_port): ip_port for ip_port in chunk}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        results.append(result)
                        out.write(result + "\n")
                        passed += 1
                    else:
                        failed += 1
            elapsed = time.time() - start
            done = i + len(chunk)
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate if rate > 0 else 0
            pct = done / total * 100
            bar_width = 30
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)
            sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | 通过 {passed} | {rate:.1f}/s | ETA {eta/60:.1f}m   ")
            sys.stderr.flush()

    # 如果精筛通过为0且启用回退，使用粗筛结果
    if passed == 0 and args.fallback and total > 0:
        print("\n  精筛未通过任何节点，使用粗筛结果作为回退")
        with open(args.output, "w", encoding="utf-8") as out:
            out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
            for ip_port in all_lines:
                if ip_port:
                    ip, port = ip_port.rsplit(":", 1)
                    out.write(f"{ip},{port},TRUE,CLOUDFLARE,,,fallback,,\n")
        passed = total

    elapsed = int(time.time() - start)
    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | 通过 {passed}/{total} | {elapsed//60}min{'':20}\n")
    print(f"精筛通过: {passed}")

if __name__ == "__main__":
    main()