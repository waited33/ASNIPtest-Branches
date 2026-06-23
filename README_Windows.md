# ASNIPtest Windows 版本使用说明

## 概述

ASNIPtest Windows 移植版本，用于从 ASN 编号出发，自动完成 IP 段拉取 → 端口扫描 → Cloudflare 反代节点检测。

### 主要特性

- **图形界面**：简单易用的 GUI 界面
- **本地 TLS 验证**：精筛使用本地 TLS 握手验证，无需依赖外部 API
- **智能回退**：精筛失败时自动保留粗筛结果，确保不丢失数据
- **中间文件保存**：每个步骤的结果都会保存，方便后续复用

## 前置依赖

### 1. Python 3.8+
- 下载地址：https://www.python.org/downloads/windows/
- 安装时勾选 **"Add Python to PATH"**

### 2. Masscan Windows 版本
- 下载地址：https://github.com/robertdavidgraham/masscan/releases
- 下载 `masscan-*-windows.zip` 文件
- 解压后将 `masscan.exe` 放到项目目录

## 文件结构

```
ASNIPtest/
├── asnip_gui.py        # GUI 图形界面程序
├── start_gui.bat       # GUI 启动脚本（双击运行）
├── cf-scanner.exe      # Cloudflare 节点检测工具（已编译）
├── masscan.exe         # 端口扫描工具（需下载）
├── verify.py           # TLS 精筛模块
├── run.bat             # 命令行启动脚本
├── run_win.py          # Windows 版本主程序
├── ports.txt           # 默认扫描端口列表
├── README_Windows.md   # 本说明文档
│
├── [中间文件 - 扫描后生成]
├── cidrs.txt           # ASN 对应的 IP 段
├── masscan_result.txt  # masscan 扫描结果
├── cf_hits.txt         # 粗筛发现的 CF 节点
├── verified.txt        # 精筛后的节点列表
└── output_*.csv        # 最终输出结果
```

## 使用方法

### 方法一：图形界面（推荐）

1. 双击 `start_gui.bat`
2. 在界面中输入 **ASN 编号**（如 `AS209242`）
3. 选择扫描端口（默认：`443,8443,2053,2083,2087,2096`）
4. 可选：勾选"启用测速"
5. 点击 **"开始扫描"**

### 方法二：命令行模式

```cmd
run.bat AS209242                    # 单个 ASN
run.bat AS209242,AS13335            # 多个 ASN
run.bat AS209242 -p 443,8443        # 自定义端口
```

### 方法三：直接运行 Python

```cmd
python asnip_gui.py                # 图形界面
python run_win.py AS209242         # 命令行模式
```

## 工作流程

```
用户输入 ASN
    │
    ▼
┌──────────────────────┐
│ 1. ASN → CIDR       │  RIPEStat API 查询该 ASN 广播的所有 IPv4 前缀
├──────────────────────┤
│ 2. masscan 端口扫描  │  高速 SYN 扫描，发现开放端口
├──────────────────────┤
│ 3. cf-scanner 粗筛   │  TLS 握手检测，筛选 Cloudflare 节点
├──────────────────────┤
│ 4. 验证             │  TLS本地验证 或 API远程验证
│                      │  ✨ 验证失败时自动保留粗筛结果
├──────────────────────┤
│ 5. 测速（可选）       │  TCP 延迟 + Cloudflare 下载速度
├──────────────────────┤
│ 输出 CSV             │  生成结果文件
└──────────────────────┘
```

## 常用 Cloudflare ASN

| ASN | 说明 |
|-----|------|
| AS209242 | Cloudflare Inc.（主 ASN） |
| AS13335 | Cloudflare Inc.（备用） |
| AS3214 | Orange S.A.（部分节点） |
| AS7473 | 新加坡 Starhub 网段 |

## 中间文件说明

扫描过程中会自动生成以下中间文件：

| 文件 | 说明 | 用途 |
|------|------|------|
| `cidrs.txt` | ASN 对应的 IP 段 | 记录查询到的 CIDR 列表 |
| `masscan_result.txt` | 端口扫描结果 | masscan 发现的所有开放端口 |
| `cf_hits.txt` | 粗筛 CF 节点 | cf-scanner 初步筛选的节点 |
| `verified.txt` | 精筛结果 | 通过 TLS 验证的节点 |

### 后期再次扫描

如果想要复用之前的扫描结果：

1. **保留中间文件**：不需要重新扫描时，不要删除 `cf_hits.txt`
2. **单独运行精筛**：
   ```cmd
   python verify.py --input cf_hits.txt --output result.csv --mode tls
   ```
3. **修改后重新运行**：编辑 `cf_hits.txt` 添加或删除节点，然后重新运行精筛

## 输出格式

运行完成后生成 CSV 文件（`output_*.csv`），包含以下列：

| 列 | 说明 | 示例 |
|---|---|---|
| IP地址 | Cloudflare 节点 IP | `162.159.192.1` |
| 端口 | TLS 端口 | `443` |
| TLS | TLS 版本 | `TRUE` |
| 数据中心 | CF 数据中心代号 | `HKG` |
| 地区 | 国家/地区代码 | `HK` |
| 城市 | 城市名 | `Hong Kong` |
| 网络延迟 | TCP 延迟 (ms) | `42` |
| 下载速度 | 下载带宽 (Mbps) | `5.12` |
| ASN | 源 ASN 编号 | `AS209242` |

> 注意：如果精筛未通过任何节点，粗筛保留的节点在"城市"列会标记为 **"粗筛保留"**

## 验证设置

程序支持两种验证模式：

### TLS 本地验证（默认）
- **优点**：无需外部 API，完全本地运行，隐私性好
- **缺点**：无法获取地理位置信息
- **适用场景**：大多数情况下推荐使用

### API 远程验证
- **优点**：可获取地理位置、数据中心等信息
- **缺点**：依赖外部 API，需要稳定的网络连接
- **适用场景**：需要详细信息时使用

### 自定义参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| 验证模式 | TLS本地验证 / API远程验证 | TLS本地验证 |
| API 地址 | API验证模式使用的接口地址 | `https://api.090227.xyz/check` |
| 验证并发 | 同时验证的连接数 | 64（根据CPU自动调整）|

> 注意：TLS本地验证在验证失败时会自动保留粗筛结果，确保不丢失数据

## 注意事项

### 权限要求
- **masscan 需要管理员权限**：右键点击命令提示符，选择"以管理员身份运行"
- GUI 启动脚本也需要以管理员权限运行

### 网络兼容性
- masscan 使用 raw socket，在某些网络环境下可能受限
- 如果扫描失败，请尝试切换网络（如使用手机热点）
- 某些 VPN 或代理可能影响扫描结果

### 扫描速率
- 默认根据 CPU 核心数自动设置
- 如果网络不稳定，建议降低扫描速率（如 1000 pps）

## 常见问题

### Q: masscan 报错 "permission denied"
**A**: 请以管理员身份运行命令提示符，masscan 需要 raw socket 权限。

### Q: 扫描速度很慢
**A**: Windows 上 masscan 性能可能不如 Linux，建议在设置中降低扫描速率。

### Q: 精筛通过数量为 0
**A**: 这是正常现象！程序会自动保留粗筛发现的所有 CF 节点（标记为"粗筛保留"）。

### Q: 如何后期再次使用之前的扫描结果？
**A**: 直接运行 `python verify.py --input cf_hits.txt --output result.csv --mode tls`

### Q: 无法获取公网 IP
**A**: 检查网络连接，确保可以访问外部网站。

## 技术支持

如有问题，请访问项目主页：https://github.com/e13815332/ASNIPtest
