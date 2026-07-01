# ASNIPtest Windows 版

基于 [D-adis/ASNIPtest-New](https://github.com/D-adis/ASNIPtest-New) 的 Windows 定制版，增加了 GUI 界面、智能速率探测、TLS 本地验证等功能。

## 功能特性

### 原版功能
- 从 ASN 拉取 IP 段
- masscan 快速端口扫描
- cf-scanner Cloudflare 节点粗筛
- API 远程验证精筛
- 下载测速

### Windows 版增强
- ✅ **图形界面 (GUI)** - 可视化操作，实时进度显示
- ✅ **智能速率探测** - 实测网卡发包上限，动态调整 masscan 速率
- ✅ **TLS 本地验证** - 不依赖外部 API，本地检测 Cloudflare 证书
- ✅ **本地 GeoIP 查询** - 内置 GeoLite2 数据库，本地查询地区/城市信息
- ✅ **国内镜像支持** - geoip2 库安装自动切换国内镜像源，解决网络超时
- ✅ **进度条显示** - 实时显示各阶段扫描进度
- ✅ **原生 Windows 支持** - 无需 WSL2，直接运行

## 系统要求

- Windows 10/11
- Python 3.8+
- [masscan.exe](https://github.com/robertdavidgraham/masscan/releases) - 端口扫描工具
- [cf-scanner.exe](https://github.com/D-adis/ASNIPtest-New/releases) - Cloudflare 节点粗筛工具
- WinPcap 或 Npcap（masscan 依赖）
  - WinPcap: https://www.winpcap.org/
  - Npcap: https://nmap.org/npcap/

> **说明**：geoip2 库和 GeoLite2-City.mmdb 数据库会在首次运行时自动下载安装，无需手动配置。

## 安装步骤

### 方法一：快速安装

1. 克隆或下载本项目
2. 下载 masscan Windows 版并解压，将 `masscan.exe` 放到项目目录
3. 下载 cf-scanner Windows 版，将 `cf-scanner.exe` 放到项目目录
4. 双击运行 `install_windows.bat` 检查依赖

### 方法二：手动安装

```bash
# 1. 克隆项目
git clone https://github.com/D-adis/ASNIPtest-New.git
cd ASNIPtest-New

# 2. 下载 masscan.exe 放到当前目录
# 下载地址: https://github.com/robertdavidgraham/masscan/releases

# 3. 编译或下载 cf-scanner.exe 放到当前目录
cd cf-scanner-src
go build -o ../cf-scanner.exe main.go
cd ..

# 4. 验证
python --version
```

## 使用方法

### 图形界面（推荐）

双击 `start_gui.bat` 启动图形界面：

1. 输入 ASN 编号（多个用逗号分隔），如 `AS209242`
2. 选择扫描端口，默认 `443,8443,2053,2083,2087,2096`
3. 选择扫描速率（自动模式会智能探测）
4. 选择验证模式：
   - **TLS 本地验证** - 本地检测证书，速度快，不依赖网络
   - **API 远程验证** - 通过 API 验证反代能力，结果更准确
5. 点击「开始扫描」

### 命令行模式

```bash
# 扫描单个 ASN
run.bat AS209242

# 扫描多个 ASN
run.bat AS209242,AS3214
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `asnip_gui.py` | 图形界面主程序 |
| `run_win.py` | Windows 命令行版本 |
| `verify.py` | 验证工具（支持 TLS 和 API 两种模式） |
| `start_gui.bat` | 启动图形界面 |
| `run.bat` | 命令行启动脚本 |
| `install_windows.bat` | Windows 安装检查脚本 |
| `ports.txt` | 扫描端口配置 |

## 验证模式说明

### TLS 本地验证
- 原理：通过 TLS 握手检测证书，并发送 HTTP 请求测试实际反代能力
- 验证条件：证书由 Cloudflare 签发 + 响应包含 `Server: cloudflare` 或 `CF-RAY` + 非 52x 错误状态码
- 优点：速度快，不依赖外部 API，无网络请求
- 缺点：准确性有限，部分非反代 IP 可能通过验证

### API 远程验证（推荐）
- 原理：通过 api.090227.xyz/check API 验证反代能力，模拟实际反代请求
- 优点：能准确确认 IP 的反代能力，结果可靠，默认模式
- 缺点：依赖外部 API，需要网络连接

### 回退机制
API 验证模式下，如果全部验证失败，会自动回退到 TLS 本地验证模式。

## 常见问题

### 1. masscan 报错找不到 npf
安装 WinPcap 或 Npcap：
- WinPcap: https://www.winpcap.org/
- Npcap: https://nmap.org/npcap/

### 2. 扫描速率上不去
- 以管理员身份运行
- 在「网络适配器」中禁用不必要的网络接口
- 使用更大的扫描速率（注意可能触发 ISP 限速）

### 3. 找不到 CF 节点
- 确认扫描的 ASN 是否正确，推荐使用 `AS209242` 或 `AS13335`
- 检查 masscan 是否正常工作
- 尝试使用 TLS 验证模式

### 4. API 验证全部失败
- 检查网络连接是否正常
- 尝试使用 TLS 本地验证模式
- 确认 API 地址是否正确

### 5. geoip2 库安装失败
- 程序会自动尝试多个国内镜像源（清华、阿里、豆瓣、中科大）
- 如果全部失败，地区/城市信息将为空，不影响其他功能
- 可手动安装：`pip install geoip2 -i https://pypi.tuna.tsinghua.edu.cn/simple`

### 6. GeoIP 数据库下载失败
- 程序会自动尝试多个下载源
- 如果全部失败，可手动下载 GeoLite2-City.mmdb 放到项目目录
- 下载地址：https://raw.gitmirror.com/adysec/IP_database/main/geolite/GeoLite2-City.mmdb

## 推荐 ASN

- **AS209242** - Cloudflare 主要 ASN，节点最多
- **AS13335** - Cloudflare 经典 ASN
- **AS3214** - 部分地区可用

## 输出文件

扫描结果保存在项目目录下，文件名格式：
`result_{ASN编号}_{时间戳}.csv`

CSV 字段：
- IP地址 - 节点 IP
- 端口 - 开放端口
- TLS - 是否支持 TLS
- 数据中心 - Cloudflare 数据中心（三字母代码）
- 地区 - 国家/地区
  - API 模式：由 API 返回
  - TLS 模式：通过本地 GeoLite2 数据库查询
- 城市 - 城市
  - API 模式：由 API 返回
  - TLS 模式：通过本地 GeoLite2 数据库查询
- 网络延迟 - 延迟(ms)
- 下载速度 - 速度(KB/s)
- ASN - ASN 编号

## License

与原项目保持一致。
