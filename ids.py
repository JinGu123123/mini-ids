import subprocess
import time
import json
import threading
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ================= 全局设置与主动防御配置 =================
# 白名单：本机和 WSL 网关（请确保这里的网关是你实际的网关，比如 172.20.224.1）
WHITELIST = ["127.0.0.1", "172.20.224.1"]  
BAN_DURATION = 10  # 封禁时长（秒，为了方便测试先改成10秒，正式环境可改为600秒）

# ================= 状态管理 =================
scan_history = defaultdict(list)
TIME_WINDOW = 5
PORT_THRESHOLD = 10

syn_flood_history = defaultdict(deque)
SYN_FLOOD_WINDOW = 1
SYN_FLOOD_THRESHOLD = 100

packet_count = 0
console = Console()

# ================= 核心函数 =================
def print_startup_banner():
    banner = Panel.fit(
        "[bold cyan]Mini-IDS 正在运行[/bold cyan]\n"
        f"[green]监听窗口:[/green] {TIME_WINDOW} 秒\n"
        f"[green]触发阈值:[/green] 单IP扫描 {PORT_THRESHOLD} 个端口",
        title="[bold yellow]🛡️ 入侵检测系统[/bold yellow]",
        border_style="blue"
    )
    console.print(banner)


def check_port_scan(src_ip, dst_port):
    now = time.time()
    scan_history[src_ip].append((now, dst_port))
    
    scan_history[src_ip] = [
        (t, p) for t, p in scan_history[src_ip] 
        if now - t <= TIME_WINDOW
    ]
    
    unique_ports = set(p for t, p in scan_history[src_ip])
    
    if len(unique_ports) >= PORT_THRESHOLD:
        alert_text = Text()
        alert_text.append("源 IP: ", style="bold white")
        alert_text.append(f"{src_ip}\n", style="bold red")
        alert_text.append("行为: ", style="bold white")
        alert_text.append(f"在 {TIME_WINDOW} 秒内扫描了 {len(unique_ports)} 个端口\n", style="bold yellow")
        
        console.print(Panel(
            alert_text,
            title="[bold red blink]🚨 警报：检测到端口扫描 🚨[/bold red blink]",
            border_style="red",
            expand=False
        ))
        scan_history[src_ip] = []

def check_syn_flood(src_ip, dst_ip, dst_port):
    now = time.time()
    target_key = (dst_ip, dst_port) 
    
    history = syn_flood_history[target_key]
    history.append(now)
    
    while history and now - history[0] > SYN_FLOOD_WINDOW:
        history.popleft()
        
    if len(history) >= SYN_FLOOD_THRESHOLD:
        alert_text = Text()
        alert_text.append("目标 IP: ", style="bold white")
        alert_text.append(f"{dst_ip}:{dst_port}\n", style="bold red")
        alert_text.append("行为: ", style="bold white")
        alert_text.append(f"在 {SYN_FLOOD_WINDOW} 秒内收到 {len(history)} 个 SYN 包\n", style="bold yellow")
        alert_text.append("最近源 IP: ", style="bold white")
        alert_text.append(f"{src_ip}\n", style="bold red")
        
        console.print(Panel(
            alert_text,
            title="[bold red blink]🚨 警报：检测到 SYN Flood 洪水攻击 🚨[/bold red blink]",
            border_style="red",
            expand=False
        ))
            
        # 触发主动防御并清空记录
        ban_ip(src_ip)
        history.clear()

def ban_ip(ip):
    """调用 iptables 封禁指定 IP"""
    if ip in WHITELIST:
        console.print(f"[bold yellow]⚠️ 白名单保护：拦截了针对 {ip} 的封禁操作[/bold yellow]")
        return

    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
        console.print(f"[bold red]🔨 联动防御：已将恶意 IP {ip} 加入防火墙黑名单[/bold red]")
        
        # 异步开启一个定时器，到期自动解封
        def unban():
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            console.print(f"[bold green]🔓 封禁到期：已解除对 IP {ip} 的封锁[/bold green]")
            
        timer = threading.Timer(BAN_DURATION, unban)
        timer.daemon = True
        timer.start()
    except Exception as e:
        console.print(f"[bold yellow]⚠️ 封禁失败: {e}[/bold yellow]")

def analyze_packet(pkt):
    global packet_count
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    packet_count += 1
    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    dst_port = tcp_layer.dport
    
    if tcp_layer.flags == 'S':
        check_port_scan(src_ip, dst_port)
        check_syn_flood(src_ip, dst_ip, dst_port)

if __name__ == "__main__":
    print_startup_banner()
    try:
        # 注意：这里指定了 eth0 网卡
        sniff(prn=analyze_packet, store=False,filter="tcp")
    except KeyboardInterrupt:
        summary = Table(title="[bold cyan]📊 本次运行统计[/bold cyan]", show_header=False)
        summary.add_row("总共抓取包数", f"[green]{packet_count}[/green]")
        console.print(summary)
        console.print("[bold yellow]👋 IDS 已安全退出[/bold yellow]")