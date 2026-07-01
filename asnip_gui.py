#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest Windows GUI - Cloudflare 节点扫描工具图形界面
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re, threading
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).parent.resolve()
MASSCAN_EXE = BASE / "masscan.exe"
CF_SCANNER_EXE = BASE / "cf-scanner.exe"
VERIFY_PY = BASE / "verify.py"
PORTS_FILE = BASE / "ports.txt"
VERSION_FILE = BASE / "VERSION"

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

class ASNIPtestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"ASNIPtest - Cloudflare 节点扫描工具 v{self.get_version()}")
        self.root.geometry("720x560")
        self.root.resizable(True, True)

        self.process = None
        self.scan_running = False
        self.cpu_cores, self.ram_mb = detect_hardware()
        self.recommended_rate = 4000
        self._anim_running = False
        self._anim_base = 0
        self._anim_range = 0
        self._anim_dots = 0

        self.setup_ui()
        self.setup_styles()
        self.update_sys_info()
        self.check_dependencies()

        self.download_geoip_db()

    def download_geoip_db(self):
        geoip_db = BASE / "GeoLite2-City.mmdb"
        if geoip_db.exists():
            self.log("GeoIP 数据库已存在")
            return
        self.log("正在后台下载 GeoIP 数据库...")
        def _download():
            import subprocess
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
                    self.log(f"  尝试: {url}")
                    ps_script = f"""
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
try {{
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile('{url}', '{geoip_db}')
    $size = (Get-Item '{geoip_db}').Length
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
                            self.log(f"  GeoIP 数据库下载成功 ({size//1024//1024}MB)")
                            return
                        else:
                            if geoip_db.exists():
                                geoip_db.unlink()
                            self.log(f"  文件太小({size}字节)，可能下载失败")
                    else:
                        err_msg = output.replace("ERROR|", "") if "ERROR|" in output else result.stderr[:80]
                        if geoip_db.exists():
                            geoip_db.unlink()
                        self.log(f"  下载失败: {err_msg}")
                except Exception as e:
                    if geoip_db.exists():
                        geoip_db.unlink()
                    self.log(f"  失败: {str(e)[:80]}")
                    continue
            self.log("GeoIP 数据库下载失败，地区信息将为空")
            self.log("提示: 请手动下载 GeoLite2-City.mmdb 放到项目目录")
            self.log("下载地址: https://raw.gitmirror.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb")
        threading.Thread(target=_download, daemon=True).start()

    def get_version(self):
        try:
            return VERSION_FILE.read_text().strip()
        except:
            return "1.0.14"

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = ttk.LabelFrame(main_frame, text="扫描设置", padding="10")
        title_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(title_frame, text="ASN 编号:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.asn_var = tk.StringVar(value="AS209242")
        self.asn_entry = ttk.Entry(title_frame, textvariable=self.asn_var, width=40)
        self.asn_entry.grid(row=0, column=1, sticky=tk.W, pady=3, padx=5)
        ttk.Label(title_frame, text="(多个用逗号分隔)").grid(row=0, column=2, sticky=tk.W, pady=3)

        ttk.Label(title_frame, text="扫描端口:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.ports_var = tk.StringVar(value="443,8443,2053,2083,2087,2096")
        self.ports_entry = ttk.Entry(title_frame, textvariable=self.ports_var, width=40)
        self.ports_entry.grid(row=1, column=1, sticky=tk.W, pady=3, padx=5)

        ttk.Label(title_frame, text="扫描速率:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.rate_var = tk.StringVar(value="自动")
        rate_options = ["自动", "500", "1000", "2000", "4000", "8000", "16000"]
        self.rate_combo = ttk.Combobox(title_frame, textvariable=self.rate_var, values=rate_options, width=15, state="readonly")
        self.rate_combo.grid(row=2, column=1, sticky=tk.W, pady=3, padx=5)

        self.enable_speed_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(title_frame, text="启用测速", variable=self.enable_speed_var).grid(row=2, column=2, sticky=tk.W, pady=3)

        ttk.Label(title_frame, text="测速网址:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.speed_url_var = tk.StringVar(value="https://speed.cloudflare.com/__down?bytes=524288")
        self.speed_url_entry = ttk.Entry(title_frame, textvariable=self.speed_url_var, width=40)
        self.speed_url_entry.grid(row=3, column=1, sticky=tk.W, pady=3, padx=5)

        verify_frame = ttk.LabelFrame(main_frame, text="验证设置", padding="10")
        verify_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(verify_frame, text="验证模式:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.verify_mode_var = tk.StringVar(value="api")
        mode_frame = ttk.Frame(verify_frame)
        mode_frame.grid(row=0, column=1, sticky=tk.W, pady=3, padx=5)
        ttk.Radiobutton(mode_frame, text="TLS本地验证", variable=self.verify_mode_var, value="tls").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="API远程验证", variable=self.verify_mode_var, value="api").pack(side=tk.LEFT, padx=5)

        ttk.Label(verify_frame, text="API 地址:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.api_url_var = tk.StringVar(value="https://api.090227.xyz/check")
        self.api_url_entry = ttk.Entry(verify_frame, textvariable=self.api_url_var, width=40)
        self.api_url_entry.grid(row=1, column=1, sticky=tk.W, pady=3, padx=5)

        ttk.Label(verify_frame, text="验证并发:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.api_concurrent_var = tk.StringVar(value="32")
        concurrent_options = ["8", "16", "32", "64", "128"]
        self.api_concurrent_combo = ttk.Combobox(verify_frame, textvariable=self.api_concurrent_var, values=concurrent_options, width=15, state="readonly")
        self.api_concurrent_combo.grid(row=2, column=1, sticky=tk.W, pady=3, padx=5)

        sys_frame = ttk.LabelFrame(main_frame, text="系统信息", padding="10")
        sys_frame.pack(fill=tk.X, pady=(0, 10))

        self.sys_info_var = tk.StringVar()
        ttk.Label(sys_frame, textvariable=self.sys_info_var).pack(anchor=tk.W)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="停止", command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="打开输出目录", command=self.open_output_dir, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="刷新检查", command=self.check_dependencies, width=15).pack(side=tk.LEFT, padx=5)

        file_btn_frame = ttk.Frame(main_frame)
        file_btn_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(file_btn_frame, text="从 cidrs.txt 开始", command=self.load_cidrs_file, width=18).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_btn_frame, text="从 cf_hits.txt 开始", command=self.load_cf_hits_file, width=18).pack(side=tk.LEFT, padx=5)

        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))

        self.progress_var = tk.StringVar(value="就绪")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(side=tk.LEFT, padx=(0, 10))
        self.progress_bar = ttk.Progressbar(progress_frame, mode="determinate", maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        log_frame = ttk.LabelFrame(main_frame, text="运行日志", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, height=12, wrap=tk.WORD, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass

        style.configure("Green.Horizontal.TProgressbar",
                       troughcolor="#e0e0e0",
                       background="#4CAF50",
                       lightcolor="#66BB6A",
                       darkcolor="#388E3C",
                       bordercolor="#BDBDBD",
                       borderwidth=1)

        style.configure("Blue.Horizontal.TProgressbar",
                       troughcolor="#e0e0e0",
                       background="#2196F3",
                       lightcolor="#64B5F6",
                       darkcolor="#1976D2",
                       bordercolor="#BDBDBD",
                       borderwidth=1)

        style.configure("Orange.Horizontal.TProgressbar",
                       troughcolor="#e0e0e0",
                       background="#FF9800",
                       lightcolor="#FFB74D",
                       darkcolor="#F57C00",
                       bordercolor="#BDBDBD",
                       borderwidth=1)

        style.configure("Purple.Horizontal.TProgressbar",
                       troughcolor="#e0e0e0",
                       background="#9C27B0",
                       lightcolor="#BA68C8",
                       darkcolor="#7B1FA2",
                       bordercolor="#BDBDBD",
                       borderwidth=1)

        style.configure("Cyan.Horizontal.TProgressbar",
                       troughcolor="#e0e0e0",
                       background="#00BCD4",
                       lightcolor="#4DD0E1",
                       darkcolor="#0097A7",
                       bordercolor="#BDBDBD",
                       borderwidth=1)

        style.configure("Red.Horizontal.TProgressbar",
                       troughcolor="#e0e0e0",
                       background="#F44336",
                       lightcolor="#EF5350",
                       darkcolor="#D32F2F",
                       bordercolor="#BDBDBD",
                       borderwidth=1)

        self.progress_bar_style = "Green.Horizontal.TProgressbar"
        self.progress_bar.configure(style=self.progress_bar_style)

    def update_sys_info(self):
        self.sys_info_var.set(f"CPU: {self.cpu_cores} 核 | 内存: {self.ram_mb} MB | 推荐速率: {self.recommended_rate} pps")

    def check_dependencies(self):
        missing = []
        if not MASSCAN_EXE.exists():
            missing.append("masscan.exe")
        if not CF_SCANNER_EXE.exists():
            missing.append("cf-scanner.exe")
        
        try:
            import geoip2
            self.log("geoip2 库已安装")
        except ImportError:
            self.log("正在安装 geoip2 库...")
            mirrors = [
                "",
                "-i https://pypi.tuna.tsinghua.edu.cn/simple",
                "-i https://mirrors.aliyun.com/pypi/simple/",
                "-i https://pypi.doubanio.com/simple/",
                "-i https://pypi.mirrors.ustc.edu.cn/simple/",
            ]
            installed = False
            for mirror in mirrors:
                try:
                    cmd = [sys.executable, "-m", "pip", "install", "geoip2", "-q"]
                    if mirror:
                        cmd.extend(mirror.split())
                    subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    import geoip2
                    self.log(f"  安装成功")
                    installed = True
                    break
                except Exception as e:
                    if mirror:
                        self.log(f"  镜像 {mirror[:30]}... 失败")
                    else:
                        self.log(f"  默认源失败")
                    continue
            if not installed:
                self.log("  geoip2 安装失败，地区信息将为空", "warning")
        
        if missing:
            self.log(f"缺少依赖: {', '.join(missing)}", "error")
            return False
        self.log("依赖检查通过")
        return True

    def log(self, msg, level="info"):
        msg = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', msg)
        msg = re.sub(r'\r', '', msg)
        msg = re.sub(r'[^\x20-\x7E\u4e00-\u9fff]', '', msg)
        if not msg.strip():
            return
        def _append():
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
        self.root.after(0, _append)

    def update_progress(self, value, text=None, style=None):
        def _update():
            if style and style != self.progress_bar_style:
                self.progress_bar_style = style
                self.progress_bar.configure(style=self.progress_bar_style)
            self.progress_bar['value'] = value
            if text:
                self.progress_var.set(text)
        self.root.after(0, _update)

    def start_progress_anim(self, base_value, range_value=5, base_text=""):
        self._anim_base = base_value
        self._anim_range = range_value
        self._anim_running = True
        self._anim_dots = 0
        self._anim_text = base_text
        self._progress_anim_tick()

    def stop_progress_anim(self):
        self._anim_running = False

    def _progress_anim_tick(self):
        if not self._anim_running:
            return
        self._anim_dots = (self._anim_dots + 1) % 4
        offset = (self._anim_dots * 0.5) * self._anim_range / 3
        value = self._anim_base + offset
        dots = "." * self._anim_dots
        text = f"{self._anim_text}{dots}"
        self.progress_bar['value'] = min(value, 99)
        self.progress_var.set(text)
        self.root.after(400, self._progress_anim_tick)

    def open_output_dir(self):
        try:
            if IS_WINDOWS:
                os.startfile(str(BASE))
            else:
                subprocess.Popen(["xdg-open", str(BASE)])
        except Exception as e:
            messagebox.showerror("错误", f"无法打开目录: {e}")

    def load_cidrs_file(self):
        cidrs_file = BASE / "cidrs.txt"
        if not cidrs_file.exists():
            messagebox.showwarning("提示", f"未找到 cidrs.txt: {cidrs_file}")
            return
        if not self.check_dependencies():
            messagebox.showerror("错误", "缺少必要依赖，请检查")
            return
        self.scan_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.progress_bar['value'] = 0
        self.progress_var.set("从 cidrs.txt 开始扫描")
        threading.Thread(target=self.run_scan_from_cidrs, daemon=True).start()

    def load_cf_hits_file(self):
        hits_file = BASE / "cf_hits.txt"
        if not hits_file.exists():
            messagebox.showwarning("提示", f"未找到 cf_hits.txt: {hits_file}")
            return
        if not self.check_dependencies():
            messagebox.showerror("错误", "缺少必要依赖，请检查")
            return
        self.scan_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.progress_bar['value'] = 50
        self.progress_var.set("从 cf_hits.txt 开始验证")
        threading.Thread(target=self.run_scan_from_cf_hits, daemon=True).start()

    def start_scan(self):
        if self.scan_running:
            return

        asn_str = self.asn_var.get().strip()
        if not asn_str:
            messagebox.showwarning("提示", "请输入 ASN 编号")
            return

        if not self.check_dependencies():
            messagebox.showerror("错误", "缺少必要依赖，请检查")
            return

        self.scan_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

        t = threading.Thread(target=self.run_scan, daemon=True)
        t.start()

    def stop_scan(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait()
            except:
                pass
        self.scan_running = False
        self.stop_progress_anim()
        self.log("扫描已停止")
        self.finish_scan()

    def finish_scan(self):
        self.scan_running = False
        self.stop_progress_anim()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_progress(100, "扫描完成", "Green.Horizontal.TProgressbar")

    def probe_masscan_rate(self):
        if not MASSCAN_EXE.exists():
            return 4000
        probe_cidr = "104.16.0.0/28"
        probe_ports = "443"
        rate = 1000
        for test_rate in [1000, 2000, 4000, 8000]:
            result_file = BASE / f"probe_{test_rate}.txt"
            cmd = [
                str(MASSCAN_EXE), probe_cidr,
                "-p", probe_ports,
                "--rate", str(test_rate),
                "-oL", str(result_file),
                "--wait", "0"
            ]
            try:
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW)
                self.process.wait(timeout=15)
                if result_file.exists():
                    try:
                        result_file.unlink()
                    except:
                        pass
                rate = test_rate
            except subprocess.TimeoutExpired:
                if self.process:
                    self.process.kill()
                if result_file.exists():
                    try:
                        result_file.unlink()
                    except:
                        pass
                break
            except Exception:
                if result_file.exists():
                    try:
                        result_file.unlink()
                    except:
                        pass
                break
            if not self.scan_running:
                break
        return max(rate, 500)

    def run_scan(self):
        try:
            asn_str = self.asn_var.get().strip()
            asns = [a.strip().replace("AS", "").replace("as", "") for a in asn_str.replace("，", ",").split(",") if a.strip()]

            self.log(f"\n开始扫描 ASN: {asn_str}")
            self.log("=" * 50)

            self.update_progress(5, "准备中...", "Blue.Horizontal.TProgressbar")

            ports = self.ports_var.get().strip()
            if not ports:
                ports = "443,8443,2053,2083,2087,2096"

            rate_str = self.rate_var.get().strip()
            if rate_str == "自动":
                self.update_progress(10, "智能速率探测中", "Blue.Horizontal.TProgressbar")
                self.root.after(0, lambda: self.start_progress_anim(10, 5, "智能速率探测中"))
                self.log("\n[步骤 1/5] 智能速率探测")
                rate = self.probe_masscan_rate()
                self.root.after(0, self.stop_progress_anim)
                self.recommended_rate = rate
                self.root.after(0, self.update_sys_info)
                self.log(f"  推荐速率: {rate} pps")
            else:
                rate = int(rate_str)

            if not self.scan_running:
                return

            self.update_progress(15, "获取 CIDR...", "Blue.Horizontal.TProgressbar")
            self.log("\n[步骤 2/5] ASN -> CIDR")
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
                        self.log(f"  AS{asn} -> {count} 个 IPv4 CIDR")
                except Exception as e:
                    self.log(f"  AS{asn} -> 失败: {e}", "error")

            cidr_file = BASE / "cidrs.txt"
            cidr_file.write_text("\n".join(cidrs), encoding="utf-8")
            self.log(f"  共 {len(cidrs)} 个 CIDR")

            if not self.scan_running:
                return

            self.update_progress(30, "端口扫描中", "Orange.Horizontal.TProgressbar")
            self.root.after(0, lambda: self.start_progress_anim(30, 8, "端口扫描中"))
            self.log("\n[步骤 3/5] masscan 端口扫描")
            self.log(f"  扫描端口: {ports}")
            self.log(f"  扫描速率: {rate} pps")
            result_file = BASE / "masscan_result.txt"

            ports_file = BASE / "ports_gui.txt"
            ports_file.write_text(ports + "\n", encoding="utf-8")

            cmd = [
                str(MASSCAN_EXE), "-iL", str(cidr_file),
                "-p", ports,
                "--rate", str(rate),
                "-oL", str(result_file),
                "--wait", "3"
            ]
            try:
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', cwd=str(BASE), creationflags=CREATE_NO_WINDOW)
                while True:
                    line = self.process.stderr.readline()
                    if not line and self.process.poll() is not None:
                        break
                    if line:
                        line_stripped = line.strip()
                        m = re.search(r"(\d+\.?\d*)%\s*done", line_stripped)
                        if m:
                            pct = float(m.group(1))
                            self.root.after(0, lambda val=pct: self.update_progress(30 + val * 0.2, f"端口扫描: {val:.1f}%", "Orange.Horizontal.TProgressbar"))
                        elif line_stripped and not line_stripped.startswith("#"):
                            self.log("  " + line_stripped)
                    if not self.scan_running:
                        self.process.kill()
                        break
                self.process.wait(timeout=60)
                if self.process.returncode != 0:
                    self.log(f"  masscan 执行失败 (返回码: {self.process.returncode})", "error")
                    self.log("  请安装 Npcap 并以管理员身份运行", "warning")
                    self.log("  Npcap 下载地址: https://nmap.org/npcap/", "warning")
                    self.root.after(0, self.stop_progress_anim)
                    self.finish_scan()
                    return
            except subprocess.TimeoutExpired:
                self.log("  masscan 超时，强制终止", "error")
                if self.process:
                    self.process.kill()
                    self.process.wait()
            except Exception as e:
                self.log(f"  masscan 运行失败: {e}", "error")
                self.log("  请检查: 1. 是否已安装 WinPcap/Npcap  2. 是否以管理员身份运行", "error")
                self.root.after(0, self.stop_progress_anim)
                self.finish_scan()
                return
            self.root.after(0, self.stop_progress_anim)

            lines = []
            if result_file.exists():
                with open(result_file, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("#") or not line.strip():
                            continue
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0] == "open":
                            lines.append(f"{parts[3]}:{parts[2]}")
                result_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.log(f"  开放端口: {len(lines)}")

            if not self.scan_running:
                return

            if len(lines) == 0:
                self.log("  无开放端口，扫描结束")
                self.finish_scan()
                return

            self.update_progress(50, "CF 粗筛中...", "Purple.Horizontal.TProgressbar")
            self.log("\n[步骤 4/5] cf-scanner 粗筛")
            hits_file = BASE / "cf_hits.txt"

            cmd = [str(CF_SCANNER_EXE), "-i", str(result_file), "-o", str(hits_file), "-c", str(min(500, self.cpu_cores * 100))]
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            for line in self.process.stdout:
                if line:
                    line_stripped = line.strip()
                    self.log("  " + line_stripped)
                    m = re.search(r"(\d+\.?\d*)%", line_stripped)
                    if m:
                        pct = float(m.group(1))
                        self.update_progress(50 + pct * 0.25, f"CF 检测: {pct:.1f}%", "Purple.Horizontal.TProgressbar")
            self.process.wait()

            if not self.scan_running:
                return

            hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace")) if hits_file.exists() else 0
            self.log(f"  CF 节点: {hits}")

            if hits == 0:
                self.log("  未发现 CF 节点，扫描结束")
                self.finish_scan()
                return

            self.update_progress(75, "验证中...", "Cyan.Horizontal.TProgressbar")
            mode = self.verify_mode_var.get()
            self.log(f"\n[步骤 5/5] {'TLS本地验证' if mode == 'tls' else 'API远程验证'}")

            verified_file = BASE / "verified.txt"
            api_url = self.api_url_var.get().strip()
            concurrent = int(self.api_concurrent_var.get())

            cmd = [
                sys.executable, str(VERIFY_PY),
                "--input", str(hits_file),
                "--output", str(verified_file),
                "--api", api_url,
                "--mode", mode,
                "--chunk", "5000",
                "--concurrent", str(concurrent),
                "--fallback"
            ]
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            for line in self.process.stdout:
                if line:
                    line_stripped = line.strip()
                    self.log("  " + line_stripped)
                    m = re.search(r"(\d+)/(\d+).*?通过 (\d+)", line_stripped)
                    if m:
                        done = int(m.group(1))
                        total = int(m.group(2))
                        if total > 0:
                            pct = done / total * 100
                            self.update_progress(75 + pct * 0.2, f"验证中: {pct:.1f}%", "Cyan.Horizontal.TProgressbar")
            self.process.wait()

            if not self.scan_running:
                return

            passed = sum(1 for _ in open(verified_file, encoding="utf-8", errors="replace")) - 1 if verified_file.exists() else 0
            self.log(f"  精筛通过: {passed}")

            if passed == 0:
                self.log("  无有效节点，保留 CF 粗筛结果")
                hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace")) if hits_file.exists() else 0
                if hits > 0:
                    self.log(f"  将 {hits} 个 CF 粗筛节点作为结果输出")
                    with open(hits_file, encoding="utf-8", errors="replace") as f:
                        cf_lines = [line.strip() for line in f if line.strip()]
                    with open(verified_file, "w", encoding="utf-8") as f:
                        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
                        for line in cf_lines:
                            if ":" in line:
                                ip_port = line.split()[0] if " " in line else line
                                ip, port = ip_port.rsplit(":", 1)
                                f.write(f"{ip},{port},TRUE,CLOUDFLARE,,,0,0,\n")
                    passed = hits
                else:
                    self.log("  无 CF 节点，扫描结束")
                    self.finish_scan()
                    return

            if self.enable_speed_var.get():
                self.update_progress(95, "测速中...", "Green.Horizontal.TProgressbar")
                self.log("\n[测速]")
                self.run_speed_test(verified_file)

            self.update_progress(98, "生成结果...", "Green.Horizontal.TProgressbar")
            self.output_csv(asns)

            self.log("\n" + "=" * 50)
            self.log("扫描完成！")
            self.finish_scan()

        except Exception as e:
            self.log(f"错误: {e}", "error")
            import traceback
            self.log(traceback.format_exc(), "error")
            self.finish_scan()

    def run_scan_from_cidrs(self):
        try:
            cidrs_file = BASE / "cidrs.txt"
            with open(cidrs_file, encoding="utf-8") as f:
                cidr_count = sum(1 for line in f if line.strip() and not line.startswith("#"))
            self.log(f"[步骤 1/4] 使用 cidrs.txt，共 {cidr_count} 个 CIDR")

            if self.rate_var.get() == "自动" and self.enable_speed_var.get():
                self.update_progress(0, "智能速率探测中", "Blue.Horizontal.TProgressbar")
                self.root.after(0, lambda: self.start_progress_anim(0, 10, "智能速率探测中"))
                self.log("\n[步骤 2/4] 智能速率探测")
                self.recommended_rate = self.probe_masscan_rate()
                self.root.after(0, self.stop_progress_anim)
                self.update_progress(15, f"推荐速率: {self.recommended_rate} pps", "Blue.Horizontal.TProgressbar")
            else:
                self.recommended_rate = int(self.rate_var.get()) if self.rate_var.get() != "自动" else 4000
                self.update_progress(15, f"使用速率: {self.recommended_rate} pps", "Blue.Horizontal.TProgressbar")

            ports = self.ports_var.get().strip()
            result_file = BASE / "masscan_result.txt"
            self.update_progress(15, "端口扫描中", "Orange.Horizontal.TProgressbar")
            self.root.after(0, lambda: self.start_progress_anim(15, 15, "端口扫描中"))
            self.log(f"\n[步骤 3/4] masscan 端口扫描")
            self.log(f"  扫描端口: {ports}")
            self.log(f"  扫描速率: {self.recommended_rate} pps")

            ports_file = BASE / "ports_gui.txt"
            ports_file.write_text(ports + "\n", encoding="utf-8")

            cmd = [
                str(MASSCAN_EXE), "-iL", str(cidrs_file),
                "-p", ports,
                "--rate", str(self.recommended_rate),
                "-oL", str(result_file),
                "--wait", "3"
            ]
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', cwd=str(BASE), creationflags=CREATE_NO_WINDOW)
            while True:
                line = self.process.stderr.readline()
                if not line and self.process.poll() is not None:
                    break
                if line:
                    line_stripped = line.strip()
                    m = re.search(r"(\d+\.?\d*)%\s*done", line_stripped)
                    if m:
                        pct = float(m.group(1))
                        self.root.after(0, lambda val=pct: self.update_progress(15 + val * 0.2, f"端口扫描: {val:.1f}%", "Orange.Horizontal.TProgressbar"))
                    elif line_stripped and not line_stripped.startswith("#"):
                        self.log("  " + line_stripped)
                if not self.scan_running:
                    self.process.kill()
                    break
            self.process.wait(timeout=60)
            self.root.after(0, self.stop_progress_anim)

            if not self.scan_running:
                return

            lines = []
            if result_file.exists():
                with open(result_file, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("#") or not line.strip():
                            continue
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0] == "open":
                            lines.append(f"{parts[3]}:{parts[2]}")
                result_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.log(f"  开放端口: {len(lines)}")

            if len(lines) == 0:
                self.log("  无开放端口，跳过 cf-scanner")
                self.log("  未发现 CF 节点，扫描结束")
                self.finish_scan()
                return

            self.update_progress(50, "CF 粗筛中...", "Purple.Horizontal.TProgressbar")
            self.log("\n[步骤 4/4] cf-scanner 粗筛")
            hits_file = BASE / "cf_hits.txt"

            cmd = [str(CF_SCANNER_EXE), "-i", str(result_file), "-o", str(hits_file), "-c", str(min(500, self.cpu_cores * 100))]
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            for line in self.process.stdout:
                if line:
                    line_stripped = line.strip()
                    self.log("  " + line_stripped)
                    m = re.search(r"(\d+\.?\d*)%", line_stripped)
                    if m:
                        pct = float(m.group(1))
                        self.update_progress(50 + pct * 0.25, f"CF 检测: {pct:.1f}%", "Purple.Horizontal.TProgressbar")
            self.process.wait()

            if not self.scan_running:
                return

            hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace")) if hits_file.exists() else 0
            self.log(f"  CF 节点: {hits}")

            if hits == 0:
                self.log("  未发现 CF 节点，扫描结束")
                self.finish_scan()
                return

            self.run_verify_and_speed(hits_file)

        except Exception as e:
            self.log(f"错误: {e}", "error")
            import traceback
            self.log(traceback.format_exc(), "error")
            self.finish_scan()

    def run_scan_from_cf_hits(self):
        try:
            hits_file = BASE / "cf_hits.txt"
            hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace"))
            self.log(f"[直接验证] 使用 cf_hits.txt，共 {hits} 个候选节点")

            self.run_verify_and_speed(hits_file)

        except Exception as e:
            self.log(f"错误: {e}", "error")
            import traceback
            self.log(traceback.format_exc(), "error")
            self.finish_scan()

    def run_verify_and_speed(self, hits_file):
        self.update_progress(75, "验证中...", "Cyan.Horizontal.TProgressbar")
        mode = self.verify_mode_var.get()
        self.log(f"\n[验证] {'TLS本地验证' if mode == 'tls' else 'API远程验证'}")

        verified_file = BASE / "verified.txt"
        api_url = self.api_url_var.get().strip()
        concurrent = int(self.api_concurrent_var.get())

        cmd = [
            sys.executable, str(VERIFY_PY),
            "--input", str(hits_file),
            "--output", str(verified_file),
            "--api", api_url,
            "--mode", mode,
            "--chunk", "5000",
            "--concurrent", str(concurrent),
            "--fallback"
        ]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        for line in self.process.stdout:
            if line:
                line_stripped = line.strip()
                self.log("  " + line_stripped)
                m = re.search(r"(\d+)/(\d+).*?通过 (\d+)", line_stripped)
                if m:
                    done = int(m.group(1))
                    total = int(m.group(2))
                    if total > 0:
                        pct = done / total * 100
                        self.update_progress(75 + pct * 0.2, f"验证中: {pct:.1f}%", "Cyan.Horizontal.TProgressbar")
        self.process.wait()

        if not self.scan_running:
            return

        passed = sum(1 for _ in open(verified_file, encoding="utf-8", errors="replace")) - 1 if verified_file.exists() else 0
        self.log(f"  精筛通过: {passed}")

        if passed == 0:
            self.log("  无有效节点，保留 CF 粗筛结果")
            hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace")) if hits_file.exists() else 0
            if hits > 0:
                self.log(f"  将 {hits} 个 CF 粗筛节点作为结果输出")
                with open(hits_file, encoding="utf-8", errors="replace") as f:
                    cf_lines = [line.strip() for line in f if line.strip()]
                with open(verified_file, "w", encoding="utf-8") as f:
                    f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
                    for line in cf_lines:
                        if ":" in line:
                            ip_port = line.split()[0] if " " in line else line
                            ip, port = ip_port.rsplit(":", 1)
                            f.write(f"{ip},{port},TRUE,CLOUDFLARE,,,0,0,\n")
                passed = hits
            else:
                self.log("  无 CF 节点，扫描结束")
                self.finish_scan()
                return

        if self.enable_speed_var.get():
            self.update_progress(95, "测速中...", "Green.Horizontal.TProgressbar")
            self.log("\n[测速]")
            self.run_speed_test(verified_file)

        self.update_progress(98, "生成结果...", "Green.Horizontal.TProgressbar")
        self.output_csv([])

        self.log("\n" + "=" * 50)
        self.log("扫描完成！")
        self.finish_scan()

    def run_speed_test(self, verified_file):
        if not verified_file.exists():
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
            self.log("  无节点，跳过")
            return

        header = lines[0]
        entries = lines[1:]
        total = len(entries)
        tested = 0
        speed_url = self.speed_url_var.get().strip()

        self.log(f"  节点数: {total}")

        with open(verified_file, "w", encoding="utf-8") as f:
            f.write(header + "\n")
            for entry in entries:
                if not self.scan_running:
                    break
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
                if tested % 5 == 0 or tested == total:
                    pct = tested / total * 100
                    self.update_progress(95 + pct * 0.05, f"测速: {tested}/{total}")
                    self.log(f"  {tested}/{total} | 延迟 {latency}ms  速度 {speed_kbps}KB/s")

        self.log(f"  测速完成: {total} 个节点")

    def output_csv(self, asns):
        verified_file = BASE / "verified.txt"
        if not verified_file.exists() or verified_file.stat().st_size == 0:
            self.log("  无结果")
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

        self.log(f"  结果: {len(lines)} 条 -> {output.name}")
        return output

def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        style.theme_use('clam')
    except:
        pass
    app = ASNIPtestGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
