# 🛡️<font color="red">Mini-IDS</font>


一个基于 Python 和 Scapy 开发的轻量级入侵检测系统 (IDS)。实时监控网络流量，支持检测常见的 **端口扫描** 与 **SYN Flood 洪水攻击**，并利用 Rich 提供高颜值的终端告警。

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 核心特性

- **双引擎检测**:
    - **端口扫描检测**:基于 5 秒滑动窗口，单 IP 访问超过 10 个不同端口即触发警告。
    - **SYN Flood 检测**:基于 1 秒滑动窗口，基于同一目标 IP+端口，超过 100 个 SYN 包即判定为洪水攻击。
- **底层协议解析**:精准抓取并解析 IP、TCP头部，只看带有 SYN 标志位的握手包。
- **终端可视化**:使用 `Rich` 库渲染带颜色的边框与闪烁警告
- **日志持久化**:告警数据自动以 JSON 格式写入 `alerts.log`，方便后续对接 ES 等分析工具

## 效果展示

> [!WARNING]
> **警报: 检测到 SYN Flood 洪水攻击**
> 目标 IP: `110.242.68.66:80`
> 行为: 在 1 秒内收到了 100 个 SYN 包
> 最近源 IP: `172.20.232.167`

<font color="red">**终端弹出红色警告，并已自动写入 alerts.log**</font>

![SYN Flood 拦截演示]![alt text](syn-flood.png)

## 快速开始

### 环境要求
- Python 3.8+
- Linux 环境
- 需要 `root` 权限(用于底层抓包)

### 安装步骤
```bash
# 1. 克隆项目
git clone git@github.com:JinGu123123/mini-ids.git
cd mini-ids

# 2. 创建虚拟环境并激活
python -m venv venv
source venv/bin/activate

# 3. 安装依赖(使用国内镜像加速)
pip install -r requirements.txt -i https:pypi.tuna.tsinghua.edu.cn/simple 
```

### 启动IDS

因为需要抓取底层网络包，必须使用 `sudo` 权限运行:

```bash
sudo ./venv/bin/python ids.py
```
启动成功后，终端会显示蓝色的监控面板

### 测试防御效果

打开两个终端窗口。第一个窗口运行IDS，第二个窗口执行以下模拟攻击脚本：
```bash
# 1. 测试端口扫描检测
# 使用 namp 扫描本机网关
namp -Pn -p 1-20 192.168.172.1
# 2. 测试 SYN Flood 洪水检测
# 使用 Python 的 Scapy 库快速发送大量 SYN 包：
sudo ./venv/bin/python -c "from scapy.all import IP, TCP, send; send(IP(dst='110.242.68.66')/TCP(dport=80, flags='S'), count=300, verbose=False)"
```

## 📁项目结构
mini-ids/
├── ids.py              # 核心检测逻辑
├── requirements.txt    # 依赖清单
├── alerts.log          # 告警日志（自动生成）
└── images/             # README 展示图片

## 🛡️关于误报与反制的设计思考
在真实的生产环境中，网络抖动可能导致合法的重试请求被误判。针对此类问题及主动防御，未来的迭代计划如下：

误报防范：引入动态白名单机制，对局域网网关、核心 DNS 等合法高并发节点进行过滤
主动反制：当触发 SYN Flood 告警时，探索联动底层 iptables 防火墙或云厂商安全组，实现“检测-封禁”的自动化防御闭环

## ⚠️免责声明
本项目仅用于网络安全学习与研究。请勿用于未授权的网络监听或攻击行为，使用者需自行承担因不当使用造成的法律责任

## 📄License
MIT