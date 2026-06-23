#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest Windows GUI 版本
从 ASN 编号出发，自动完成 IP 段拉取 → 端口扫描 → Cloudflare 反代节点检测
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import sys
import os
import subprocess
import json
import urllib.request
import multiprocessing
import socket
import time
import re
from pathlib import Path
from datetime import datetime
import ctypes

# 设置高DPI支持
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

class ASNIPtestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ASNIPtest - Cloudflare 节点扫描工具 v1.1.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # 设置图标（如果存在）
        icon_path = Path(__file__).parent / "icon.ico"
        if icon_path.exists():
            root.iconbitmap(str(icon_path))
        
        # 变量
        self.asn_var = tk.StringVar()
        self.ports_var = tk.StringVar(value="443,8443,2053,2083,2087,2096")
        self.speed_test_var = tk.BooleanVar(value=False)
        self.speed_test_url_var = tk.StringVar(value="https://speed.cloudflare.com/__down?bytes=1048576")
        self.rate_var = tk.StringVar(value="自动")
        
        # 验证设置
        self.verify_mode_var = tk.StringVar(value="tls")  # tls 或 api
        self.verify_api_var = tk.StringVar(value="https://api.090227.xyz/check")
        self.verify_concurrent_var = tk.IntVar(value=64)
        
        self.is_running = False
        self.process = None
        
        # 硬件信息
        self.cpu_cores = multiprocessing.cpu_count()
        self.ram_mb = self.get_ram_mb()
        
        self.setup_ui()
        self.check_dependencies()
        
    def get_ram_mb(self):
        try:
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
            return stat.ullAvailPhys // (1024 * 1024)
        except:
            return 512
    
    def setup_ui(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ===== 输入区域 =====
        input_frame = ttk.LabelFrame(main_frame, text="扫描设置", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # ASN 输入
        asn_frame = ttk.Frame(input_frame)
        asn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(asn_frame, text="ASN 编号:", width=12).pack(side=tk.LEFT)
        asn_entry = ttk.Entry(asn_frame, textvariable=self.asn_var, width=50)
        asn_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(asn_frame, text="(多个用逗号分隔，如: AS209242,AS3214)", foreground="gray").pack(side=tk.LEFT)
        
        # 端口输入
        port_frame = ttk.Frame(input_frame)
        port_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(port_frame, text="扫描端口:", width=12).pack(side=tk.LEFT)
        port_entry = ttk.Entry(port_frame, textvariable=self.ports_var, width=50)
        port_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(port_frame, text="(如: 443 或 1-1000 或 443,8443)", foreground="gray").pack(side=tk.LEFT)
        
        # 选项
        options_frame = ttk.Frame(input_frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(options_frame, text="扫描速率:", width=12).pack(side=tk.LEFT)
        rate_combo = ttk.Combobox(options_frame, textvariable=self.rate_var, width=15, state="readonly")
        rate_combo['values'] = ("自动", "1000", "2000", "5000", "10000", "20000")
        rate_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(options_frame, text="启用测速", variable=self.speed_test_var).pack(side=tk.LEFT, padx=20)
        
        # 测速网址
        speed_url_frame = ttk.Frame(input_frame)
        speed_url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(speed_url_frame, text="测速网址:", width=12).pack(side=tk.LEFT)
        speed_url_entry = ttk.Entry(speed_url_frame, textvariable=self.speed_test_url_var, width=70)
        speed_url_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(speed_url_frame, text="(默认: Cloudflare 测速)", foreground="gray").pack(side=tk.LEFT)
        
        # ===== 验证设置 =====
        verify_frame = ttk.LabelFrame(input_frame, text="验证设置", padding="10")
        verify_frame.pack(fill=tk.X, pady=(10, 5))
        
        # 验证模式
        verify_mode_frame = ttk.Frame(verify_frame)
        verify_mode_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(verify_mode_frame, text="验证模式:", width=12).pack(side=tk.LEFT)
        ttk.Radiobutton(verify_mode_frame, text="TLS本地验证", variable=self.verify_mode_var, value="tls", 
                        command=self.on_verify_mode_change).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(verify_mode_frame, text="API远程验证", variable=self.verify_mode_var, value="api",
                        command=self.on_verify_mode_change).pack(side=tk.LEFT, padx=5)
        
        # API地址
        self.api_url_frame = ttk.Frame(verify_frame)
        self.api_url_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(self.api_url_frame, text="API 地址:", width=12).pack(side=tk.LEFT)
        self.api_url_entry = ttk.Entry(self.api_url_frame, textvariable=self.verify_api_var, width=50)
        self.api_url_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.api_url_frame, text="(API验证模式使用)", foreground="gray").pack(side=tk.LEFT)
        
        # 并发数
        concurrent_frame = ttk.Frame(verify_frame)
        concurrent_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(concurrent_frame, text="验证并发:", width=12).pack(side=tk.LEFT)
        concurrent_combo = ttk.Combobox(concurrent_frame, textvariable=self.verify_concurrent_var, width=15, state="readonly")
        concurrent_combo['values'] = (16, 32, 64, 128, 256)
        concurrent_combo.pack(side=tk.LEFT, padx=5)
        ttk.Label(concurrent_frame, text=f"推荐: {min(self.cpu_cores * 16, 64)} (CPU {self.cpu_cores} 核)", foreground="gray").pack(side=tk.LEFT)
        
        # 初始化验证模式显示
        self.on_verify_mode_change()
        
        # ===== 系统信息 =====
        info_frame = ttk.LabelFrame(main_frame, text="系统信息", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        info_text = f"CPU: {self.cpu_cores} 核  |  内存: {self.ram_mb} MB  |  推荐速率: {min(self.cpu_cores * 1000, 16000)} pps"
        ttk.Label(info_frame, text=info_text).pack(side=tk.LEFT)
        
        # ===== 操作按钮 =====
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(button_frame, text="▶ 开始扫描", command=self.start_scan, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="⏹ 停止", command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="📂 打开输出目录", command=self.open_output_dir, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔄 刷新检查", command=self.refresh_check, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📋 查看帮助", command=self.show_help, width=15).pack(side=tk.LEFT, padx=5)
        
        # ===== 进度条 =====
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="就绪")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=400)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
        
        # ===== 日志输出 =====
        log_frame = ttk.LabelFrame(main_frame, text="运行日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 配置日志颜色标签
        self.log_text.tag_config("info", foreground="black")
        self.log_text.tag_config("success", foreground="green")
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("progress", foreground="blue")
        
        # ===== 状态栏 =====
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
    def log(self, message, tag="info"):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def check_dependencies(self):
        """检查依赖"""
        base = Path(__file__).parent
        self.deps_ok = True
        
        # 检查 cf-scanner.exe
        cf_scanner = base / "cf-scanner.exe"
        if not cf_scanner.exists():
            self.log("⚠️ cf-scanner.exe 未找到", "warning")
            self.deps_ok = False
        
        # 检查 masscan.exe
        masscan = base / "masscan.exe"
        if not masscan.exists():
            self.log("⚠️ masscan.exe 未找到", "warning")
            self.log("   请从 https://github.com/robertdavidgraham/masscan/releases 下载 Windows 版本", "warning")
            self.log("   并将 masscan.exe 放到当前目录", "warning")
            self.deps_ok = False
        
        # 检查 verify.py
        verify_py = base / "verify.py"
        if not verify_py.exists():
            self.log("⚠️ verify.py 未找到", "warning")
            self.deps_ok = False
        
        if not self.deps_ok:
            self.start_btn.config(state=tk.DISABLED)
            self.status_var.set("缺少依赖，请检查日志")
            
    def refresh_check(self):
        """刷新依赖检查"""
        self.log_text.delete(1.0, tk.END)
        self.check_dependencies()
        if self.deps_ok:
            self.status_var.set("依赖检查通过")
            self.start_btn.config(state=tk.NORMAL)
    
    def on_verify_mode_change(self):
        """验证模式切换"""
        if self.verify_mode_var.get() == "api":
            self.api_url_entry.config(state=tk.NORMAL)
        else:
            self.api_url_entry.config(state=tk.DISABLED)
            
    def start_scan(self):
        """开始扫描"""
        # 验证输入
        asn_input = self.asn_var.get().strip()
        if not asn_input:
            messagebox.showerror("错误", "请输入 ASN 编号")
            return
        
        # 解析 ASN
        asns = []
        for a in asn_input.replace("，", ",").split(","):
            a = a.strip().replace("AS", "").replace("as", "")
            if a:
                asns.append(a)
        
        if not asns:
            messagebox.showerror("错误", "请输入有效的 ASN 编号")
            return
        
        # 更新UI状态
        self.is_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        self.log("=" * 50, "info")
        self.log(f"开始扫描 ASN: {', '.join('AS' + a for a in asns)}", "info")
        
        # 启动扫描线程
        thread = threading.Thread(target=self.run_scan, args=(asns,), daemon=True)
        thread.start()
        
    def stop_scan(self):
        """停止扫描"""
        self.is_running = False
        if self.process:
            try:
                self.process.terminate()
            except:
                pass
        self.log("用户中止扫描", "warning")
        self.finish_scan()
        
    def finish_scan(self):
        """完成扫描"""
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("就绪")
        
    def run_scan(self, asns):
        """执行扫描"""
        try:
            base = Path(__file__).parent
            
            # Step 1: ASN → CIDR
            self.progress_var.set("步骤 1/5: 获取 CIDR...")
            self.log("\n[步骤 1/5] ASN → CIDR", "info")
            
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
                        self.log(f"  AS{asn} → {count} 个 IPv4 CIDR", "success")
                except Exception as e:
                    self.log(f"  AS{asn} → 失败: {e}", "error")
            
            if not cidrs:
                self.log("未获取到任何 CIDR", "error")
                self.finish_scan()
                return
            
            cidr_file = base / "cidrs.txt"
            cidr_file.write_text("\n".join(cidrs))
            self.log(f"  共 {len(cidrs)} 个 CIDR", "success")
            self.progress_bar['value'] = 20
            
            if not self.is_running:
                return
            
            # Step 2: masscan 端口扫描
            self.progress_var.set("步骤 2/5: 端口扫描...")
            self.log("\n[步骤 2/5] masscan 端口扫描", "info")
            
            masscan_exe = base / "masscan.exe"
            if not masscan_exe.exists():
                self.log("  masscan.exe 未找到，跳过端口扫描", "error")
                self.log("  请从 https://github.com/robertdavidgraham/masscan/releases 下载", "warning")
                self.finish_scan()
                return
            
            result_file = base / "masscan_result.txt"
            ports = self.ports_var.get()
            
            # 获取速率
            rate_str = self.rate_var.get()
            if rate_str == "自动":
                rate = min(self.cpu_cores * 1000, 16000)
            else:
                rate = int(rate_str)
            
            self.log(f"  扫描端口: {ports}", "info")
            self.log(f"  扫描速率: {rate} pps", "info")
            
            cmd = [
                str(masscan_exe), "-iL", str(cidr_file),
                "-p", ports,
                "--rate", str(rate),
                "-oL", str(result_file),
                "--wait", "3"
            ]
            
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, cwd=str(base), creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # 读取输出
            while True:
                line = self.process.stderr.readline()
                if not line and self.process.poll() is not None:
                    break
                if line:
                    m = re.search(r"(\d+\.?\d*)%\s*done", line)
                    if m:
                        pct = float(m.group(1))
                        self.progress_bar['value'] = 20 + pct * 0.3
                        self.progress_var.set(f"端口扫描: {pct:.1f}%")
            
            self.process.wait()
            
            if self.process.returncode != 0:
                self.log("  masscan 执行失败", "error")
                self.finish_scan()
                return
            
            # 解析结果
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
            self.log(f"  开放端口: {len(lines)}", "success")
            self.progress_bar['value'] = 50
            
            if not self.is_running:
                return
            
            if len(lines) == 0:
                self.log("无开放端口，扫描结束", "warning")
                self.finish_scan()
                return
            
            # Step 3: cf-scanner 粗筛
            self.progress_var.set("步骤 3/5: CF 节点检测...")
            self.log("\n[步骤 3/5] cf-scanner 粗筛", "info")
            
            cf_scanner_exe = base / "cf-scanner.exe"
            hits_file = base / "cf_hits.txt"
            
            if not cf_scanner_exe.exists():
                self.log("  cf-scanner.exe 未找到", "error")
                self.finish_scan()
                return
            
            concurrency = max(200, min(self.cpu_cores * 100, 500))
            
            self.process = subprocess.Popen(
                [str(cf_scanner_exe), "-i", str(result_file), "-o", str(hits_file), "-c", str(concurrency)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=str(base), creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            while True:
                line = self.process.stdout.readline()
                if not line and self.process.poll() is not None:
                    break
                if line:
                    m = re.search(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)", line)
                    if m:
                        pct = float(m.group(2))
                        self.progress_bar['value'] = 50 + pct * 0.2
                        self.progress_var.set(f"CF 检测: {pct:.1f}%")
            
            self.process.wait()
            
            hits = sum(1 for _ in open(hits_file)) if hits_file.exists() else 0
            self.log(f"  CF 节点: {hits}", "success")
            self.progress_bar['value'] = 70
            
            if not self.is_running:
                return
            
            if hits == 0:
                self.log("无 CF 节点，扫描结束", "warning")
                self.finish_scan()
                return
            
            # Step 4: 精筛
            verify_mode = self.verify_mode_var.get()
            verify_concurrent = self.verify_concurrent_var.get()
            verify_api = self.verify_api_var.get().strip()
            
            mode_text = "TLS本地验证" if verify_mode == "tls" else "API远程验证"
            self.progress_var.set(f"步骤 4/5: {mode_text}...")
            self.log(f"\n[步骤 4/5] {mode_text}", "info")
            
            verify_py = base / "verify.py"
            verified_file = base / "verified.txt"
            
            if not verify_py.exists():
                self.log("  verify.py 未找到", "error")
                self.finish_scan()
                return
            
            # 构建验证命令
            cmd = [
                sys.executable, str(verify_py),
                "--input", str(hits_file),
                "--output", str(verified_file),
                "--mode", verify_mode,
                "--chunk", "5000",
                "--concurrent", str(verify_concurrent),
                "--fallback"
            ]
            
            # API模式添加API地址
            if verify_mode == "api" and verify_api:
                cmd.extend(["--api", verify_api])
                self.log(f"  API地址: {verify_api}", "info")
            
            self.log(f"  验证并发: {verify_concurrent}", "info")
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=str(base), creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            while True:
                line = self.process.stdout.readline()
                if not line and self.process.poll() is not None:
                    break
                if line:
                    m = re.search(r"\[(.+?)\].*?(\d+\.?\d*)%", line)
                    if m:
                        pct = float(m.group(2))
                        self.progress_bar['value'] = 70 + pct * 0.2
                        self.progress_var.set(f"验证中: {pct:.1f}%")
            
            self.process.wait()
            
            passed = sum(1 for _ in open(verified_file)) - 1 if verified_file.exists() else 0  # 减去标题行
            self.log(f"  精筛通过: {passed}", "success")
            self.progress_bar['value'] = 90
            
            if not self.is_running:
                return
            
            # Step 5: 测速（可选）
            if self.speed_test_var.get():
                self.progress_var.set("步骤 5/5: 测速...")
                self.log("\n[步骤 5/5] 测速", "info")
                self.run_speed_test(verified_file)
            
            # 输出结果
            self.output_result(asns, verified_file)
            
            self.progress_bar['value'] = 100
            self.progress_var.set("扫描完成")
            self.log("\n✓ 扫描完成！", "success")
            
        except Exception as e:
            self.log(f"错误: {e}", "error")
        finally:
            self.finish_scan()
    
    def run_speed_test(self, verified_file):
        """执行测速"""
        if not verified_file.exists():
            return
        
        lines = []
        with open(verified_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("IP地址"):
                    continue
                if line.count(",") >= 8:
                    lines.append(line)
        
        if not lines:
            return
        
        total = len(lines)
        tested = 0
        
        with open(verified_file, "w", encoding="utf-8") as f:
            f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
            
            for entry in lines:
                if not self.is_running:
                    break
                    
                parts = entry.split(",")
                if len(parts) < 9:
                    continue
                
                ip, port = parts[0], parts[1]
                
                # TCP 延迟
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
                
                # 下载速度
                speed_mbps = 0
                if latency > 0:
                    try:
                        import tempfile
                        from urllib.parse import urlparse
                        
                        speed_test_url = self.speed_test_url_var.get().strip()
                        if not speed_test_url:
                            speed_test_url = "https://speed.cloudflare.com/__down?bytes=1048576"
                        
                        # 从网址提取域名
                        parsed = urlparse(speed_test_url)
                        domain = parsed.hostname or "speed.cloudflare.com"
                        url_port = parsed.port or 443
                        
                        with tempfile.NamedTemporaryFile(delete=False) as tmp:
                            tmp_path = tmp.name
                        
                        r = subprocess.run(
                            ["curl", "--connect-to", f"{domain}:{url_port}:{ip}:{port}",
                             "-o", tmp_path, "-s", "-w", "%{speed_download}",
                             "--connect-timeout", "5", "--max-time", "10",
                             speed_test_url],
                            capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
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
                self.progress_var.set(f"测速: {tested}/{total} ({pct:.1f}%)")
        
        self.log(f"  测速完成: {tested} 个节点", "success")
    
    def output_result(self, asns, verified_file):
        """输出结果"""
        base = Path(__file__).parent
        
        if not verified_file.exists():
            return
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_tag = "_".join(asns)
        output = base / f"output_{asn_tag}_{ts}.csv"
        
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
        
        self.log(f"\n结果: {len(lines)} 条 → {output.name}", "success")
        self.status_var.set(f"完成: {output.name}")
        
        # 询问是否打开文件
        if messagebox.askyesno("扫描完成", f"找到 {len(lines)} 个节点\n\n是否打开结果文件？"):
            os.startfile(str(output))
    
    def open_output_dir(self):
        """打开输出目录"""
        base = Path(__file__).parent
        os.startfile(str(base))
    
    def show_help(self):
        """显示帮助"""
        help_text = """ASNIPtest - Cloudflare 节点扫描工具

【使用方法】
1. 输入 ASN 编号（如 AS209242，多个用逗号分隔）
2. 选择扫描端口（默认 443,8443,2053,2083,2087,2096）
3. 点击"开始扫描"

【工作流程】
1. ASN → CIDR：查询 RIPEStat API 获取 IP 段
2. masscan 端口扫描：高速 SYN 扫描
3. cf-scanner 粗筛：TLS 握手检测 Cloudflare 节点
4. API 精筛：二次验证节点可用性
5. 测速（可选）：TCP 延迟 + 下载速度测试

【注意事项】
• masscan 需要管理员权限运行
• 扫描速率建议根据网络情况调整
• 首次使用请确保 masscan.exe 已下载

【输出格式】
CSV 文件包含：IP地址、端口、TLS、数据中心、地区、城市、网络延迟、下载速度、ASN
"""
        messagebox.showinfo("使用帮助", help_text)


def main():
    root = tk.Tk()
    app = ASNIPtestGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
