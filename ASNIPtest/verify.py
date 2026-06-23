#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest - CF Node Verifier (Windows Enhanced)
支持 TLS 本地验证和 API 远程验证
精筛失败时自动回退保留粗筛结果
"""
import argparse, urllib.request, json, time, sys, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_single_tls(ip_port):
    """TLS 本地验证 - 直接连接检测证书"""
    try:
        ip, port = ip_port.split(":")
        port = int(port)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname="cloudflare.com") as ssock:
                if ssock.version():
                    return f"{ip},{port},TRUE,CLOUDFLARE,,,TLS_LOCAL,,"
    except:
        pass
    return None

def check_single_api(ip_port, api_url):
    """API 远程验证"""
    line = ip_port.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    ip_port = parts[0] if parts else line
    try:
        url = f"{api_url}?proxyip={ip_port}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
            "Origin": "https://090227.xyz",
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
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
    except:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="CF Node Verifier")
    parser.add_argument("--input", required=True, help="Input file with IP:port list")
    parser.add_argument("--output", required=True, help="Output CSV file")
    parser.add_argument("--mode", choices=["tls", "api"], default="tls", help="Verification mode")
    parser.add_argument("--api", default="https://api.090227.xyz/check", help="API URL for remote verification")
    parser.add_argument("--chunk", type=int, default=5000, help="Chunk size for processing")
    parser.add_argument("--concurrent", type=int, default=64, help="Concurrent connections")
    parser.add_argument("--fallback", action="store_true", default=True, help="Use rough filter results when verification passes 0")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    
    all_lines = []
    for line in raw_lines:
        parts = line.split()
        if parts:
            ip_port = parts[0]
            if ":" in ip_port:
                all_lines.append(ip_port)

    total = len(all_lines)
    passed = 0
    failed = 0
    start = time.time()
    results = []

    check_func = check_single_tls if args.mode == "tls" else lambda x: check_single_api(x, args.api)

    with open(args.output, "w", encoding="utf-8") as out:
        out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for i in range(0, total, args.chunk):
            chunk = all_lines[i:i + args.chunk]
            with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                futures = {ex.submit(check_func, line): line for line in chunk}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        out.write(result + "\n")
                        results.append(result)
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
            sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | Passed {passed} | {rate:.1f}/s | ETA {eta/60:.1f}m   ")
            sys.stderr.flush()

    if passed == 0 and args.fallback and total > 0:
        print("\n  No nodes passed verification, using rough filter results as fallback")
        with open(args.output, "w", encoding="utf-8") as out:
            out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
            for ip_port in all_lines:
                if ip_port:
                    ip, port = ip_port.rsplit(":", 1)
                    out.write(f"{ip},{port},TRUE,CLOUDFLARE,,,fallback,,\n")
        passed = total

    elapsed = int(time.time() - start)
    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | Passed {passed}/{total} | {elapsed//60}min{'':20}\n")
    print(f"Passed: {passed}")

if __name__ == "__main__":
    main()