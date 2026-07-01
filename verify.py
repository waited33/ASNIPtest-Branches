#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF 节点验证 - 支持 API 远程验证和 TLS 本地验证
API 模式: 调用 api.090227.xyz/check 验证反代能力
TLS 模式: 本地检测 Cloudflare 证书指纹
GeoIP: 使用 MaxMind GeoLite2 数据库本地查询地区信息
"""
import argparse, urllib.request, json, time, sys, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

GEOIP_DB = Path(__file__).parent / "GeoLite2-City.mmdb"
geoip_reader = None

try:
    import geoip2.database
    if GEOIP_DB.exists():
        geoip_reader = geoip2.database.Reader(str(GEOIP_DB))
except ImportError:
    pass
except Exception:
    geoip_reader = None

CF_ISSUERS = [
    "Cloudflare Inc ECC CA-2",
    "Cloudflare Inc ECC CA-3",
    "Cloudflare RSA Certification Authority",
    "Cloudflare Inc RSA CA-2",
    "Cloudflare",
]

def get_geo_info(ip):
    """从本地 GeoIP 数据库获取地区信息"""
    if not geoip_reader:
        return "", ""
    try:
        response = geoip_reader.city(ip)
        country = response.country.name or ""
        city = response.city.name or ""
        return country, city
    except Exception:
        return "", ""

def install_geoip2():
    """自动安装 geoip2 库，支持多个 pip 镜像源"""
    try:
        import geoip2
        return True
    except ImportError:
        pass
    print("正在安装 geoip2 库...", file=sys.stderr)
    import subprocess
    mirrors = [
        "",
        "-i https://pypi.tuna.tsinghua.edu.cn/simple",
        "-i https://mirrors.aliyun.com/pypi/simple/",
        "-i https://pypi.doubanio.com/simple/",
        "-i https://pypi.mirrors.ustc.edu.cn/simple/",
    ]
    for mirror in mirrors:
        try:
            cmd = [sys.executable, "-m", "pip", "install", "geoip2", "-q"]
            if mirror:
                cmd.extend(mirror.split())
            subprocess.check_call(cmd)
            print("  安装成功", file=sys.stderr)
            return True
        except Exception as e:
            if mirror:
                print(f"  镜像 {mirror} 失败: {str(e)[:60]}", file=sys.stderr)
            else:
                print(f"  默认源失败: {str(e)[:60]}", file=sys.stderr)
            continue
    print("  所有镜像均安装失败，地区信息将为空", file=sys.stderr)
    return False

def download_geoip_db():
    """自动下载 GeoIP 数据库"""
    if GEOIP_DB.exists():
        return True
    print("正在下载 GeoIP 数据库...", file=sys.stderr)
    urls = [
        "https://git.io/GeoLite2-City.mmdb",
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/master/GeoLite2-City.mmdb",
        "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@master/GeoLite2-City.mmdb",
        "https://raw.githubusercontentcontent.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb",
        "https://cdn.jsdelivr.net/gh/adysec/IP_database@main/geolite/GeoLite2-City.mmdb",
        "https://raw.gitmirror.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb",
        "https://ghproxy.net/https://raw.githubusercontent.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb",
        "https://gh.api.99988866.xyz/https://raw.githubusercontent.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb",
        "https://raw.githubusercontent.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb",
    ]
    for url in urls:
        try:
            print(f"  尝试: {url}", file=sys.stderr)
            ps_script = f"""
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
try {{
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile('{url}', '{GEOIP_DB}')
    $size = (Get-Item '{GEOIP_DB}').Length
    Write-Output "SUCCESS|$size"
}} catch {{
    Write-Output "ERROR|$($_.Exception.Message)"
}}
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, text=True, timeout=330
            )
            output = result.stdout.strip()
            if output.startswith("SUCCESS|"):
                size = int(output.split("|")[1])
                if size > 1024 * 1024:
                    print(f"  下载成功 ({size//1024//1024}MB)", file=sys.stderr)
                    return True
                else:
                    if GEOIP_DB.exists():
                        GEOIP_DB.unlink()
                    print(f"  文件太小({size}字节)", file=sys.stderr)
            else:
                err_msg = output.replace("ERROR|", "") if "ERROR|" in output else result.stderr[:80]
                if GEOIP_DB.exists():
                    GEOIP_DB.unlink()
                print(f"  失败: {err_msg}", file=sys.stderr)
        except Exception as e:
            if GEOIP_DB.exists():
                GEOIP_DB.unlink()
            print(f"  失败: {e}", file=sys.stderr)
            continue
    print("GeoIP 数据库下载失败，将跳过地区信息", file=sys.stderr)
    print("提示: 请手动下载 GeoLite2-City.mmdb 放到项目目录", file=sys.stderr)
    print("下载地址: https://raw.gitmirror.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb", file=sys.stderr)
    return False

def check_single_tls(ip_port):
    """TLS 本地验证 - 验证反代能力"""
    line = ip_port.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    ip_port = parts[0] if parts else line
    try:
        ip, port = ip_port.rsplit(":", 1)
        port = int(port)
        test_domains = [
            "www.cloudflare.com",
            "www.google.com",
            "www.microsoft.com",
            "github.com",
            "www.baidu.com",
        ]
        for domain in test_domains:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        if not ssock.version():
                            continue
                        ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n" % domain.encode())
                        response = b""
                        timeout = 5
                        start = time.time()
                        while time.time() - start < timeout:
                            try:
                                ssock.settimeout(timeout - (time.time() - start))
                                chunk = ssock.recv(4096)
                                if not chunk:
                                    break
                                response += chunk
                                if b"\r\n\r\n" in response:
                                    break
                            except socket.timeout:
                                break
                        response_str = response.decode("utf-8", errors="ignore")
                        if "Server: cloudflare" not in response_str and "CF-RAY:" not in response_str:
                            continue
                        status_code = int(response_str.split()[1]) if len(response_str.split()) > 1 else 0
                        if status_code >= 520 and status_code <= 527:
                            continue
                        country, city = get_geo_info(ip)
                        return f"{ip},{port},TRUE,CLOUDFLARE,{country},{city},,,"
            except Exception:
                continue
    except Exception:
        pass
    return None

def check_single_api(line, api_url):
    """API 远程验证 - 验证 CF 反代能力"""
    line = line.strip()
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
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="CF 节点验证工具")
    parser.add_argument("--input", required=True, help="输入文件 (IP:port 列表)")
    parser.add_argument("--output", required=True, help="输出文件 (CSV 格式)")
    parser.add_argument("--api", default="https://api.090227.xyz/check", help="API 地址")
    parser.add_argument("--mode", default="api", choices=["api", "tls"], help="验证模式: api 或 tls")
    parser.add_argument("--chunk", type=int, default=5000, help="分片大小")
    parser.add_argument("--concurrent", type=int, default=32, help="并发数")
    parser.add_argument("--fallback", action="store_true", help="API 失败时回退到 TLS 验证")
    args = parser.parse_args()

    global geoip_reader
    install_geoip2()
    download_geoip_db()
    try:
        if GEOIP_DB.exists():
            import geoip2.database
            geoip_reader = geoip2.database.Reader(str(GEOIP_DB))
            print("GeoIP 数据库加载成功", file=sys.stderr)
        else:
            print("GeoIP 数据库不存在，地区信息将为空", file=sys.stderr)
    except Exception as e:
        print(f"GeoIP 数据库加载失败: {e}", file=sys.stderr)

    with open(args.input, encoding="utf-8", errors="replace") as f:
        all_lines = [l for l in f if l.strip() and not l.startswith("#")]

    total = len(all_lines)
    if total == 0:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        print("无输入节点", file=sys.stderr)
        return

    passed = 0
    failed = 0
    start = time.time()

    verify_func = check_single_tls if args.mode == "tls" else lambda l: check_single_api(l, args.api)

    with open(args.output, "w", encoding="utf-8") as out:
        out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for i in range(0, total, args.chunk):
            chunk = all_lines[i:i + args.chunk]
            with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                futures = {ex.submit(verify_func, line): line for line in chunk}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        out.write(result + "\n")
                        passed += 1
                    else:
                        failed += 1
            elapsed = time.time() - start
            done = i + len(chunk)
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate if rate > 0 else 0
            sys.stderr.write(f"\r{done}/{total} | 通过 {passed} | {rate:.1f}/s | ETA {eta/60:.1f}m   ")
            sys.stderr.flush()

    if passed == 0 and args.fallback and args.mode == "api" and total > 0:
        print("\n  WARNING: API 验证全部失败，回退到 TLS 本地验证...", file=sys.stderr)
        passed = 0
        failed = 0
        start = time.time()
        with open(args.output, "w", encoding="utf-8") as out:
            out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
            for i in range(0, total, args.chunk):
                chunk = all_lines[i:i + args.chunk]
                with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                    futures = {ex.submit(check_single_tls, line): line for line in chunk}
                    for f in as_completed(futures):
                        result = f.result()
                        if result:
                            out.write(result + "\n")
                            passed += 1
                        else:
                            failed += 1
                elapsed = time.time() - start
                done = i + len(chunk)
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0
                sys.stderr.write(f"\r[TLS回退] {done}/{total} | 通过 {passed} | {rate:.1f}/s | ETA {eta/60:.1f}m   ")
                sys.stderr.flush()

    elapsed = int(time.time() - start)
    sys.stderr.write(f"\n完成 | {elapsed//60}min | 通过 {passed}/{total}\n")

if __name__ == "__main__":
    main()
