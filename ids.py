import time
import json
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from collections import deque

# ================= 初始化 Rich 控制台 =================
console = Console()

# ================= 状态管理 =================
scan_history = defaultdict(list)
TIME_WINDOW = 5
PORT_THRESHOLD = 10

# 全局流量计数器
packet_count = 0
syn_flood_history = defaultdict(deque)
SYN_FLOOD_WINDOW = 1
SYN_FLOOD_THRESHOLD = 100

def print_startup_banner():
    """打印启动时的横幅"""
    banner = Panel.fit(
        "[bold cyan]Mini-IDS 正在运行[/bold cyan]\n"
        f"[green]监听窗口:[/green] {TIME_WINDOW} 秒\n"
        f"[green]触发阈值:[/green] 单IP扫描 {PORT_THRESHOLD} 个端口",
        title="[bold yellow]🛡️ 入侵检测系统[/bold yellow]",
        border_style="blue"
    )
    console.print(banner)

def check_port_scan(src_ip, dst_port):
    global packet_count
    now = time.time()
    scan_history[src_ip].append((now, dst_port))
    
    # 清理过期记录
    scan_history[src_ip] = [
        (t, p) for t, p in scan_history[src_ip] 
        if now - t <= TIME_WINDOW
    ]
    
    unique_ports = set(p for t, p in scan_history[src_ip])
    
    if len(unique_ports) >= PORT_THRESHOLD:
        # 1. 构造告警数据
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": "PORT_SCAN",
            "source_ip": src_ip,
            "port_count": len(unique_ports),
            "duration_seconds": TIME_WINDOW
        }
        
        # 2. 使用 Rich 打印炫酷告警框
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
        
        # 3. 写入 JSON 文件
        with open("alerts.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_data, ensure_ascii=False) + "\n")
        
        # 清空记录，防止同一次扫描疯狂报警
        scan_history[src_ip] = []

def check_syn_flood(src_ip,dst_ip,dst_port):
    now = time.time()
    target_key = (dst_ip,dst_port)

    history = syn_flood_history[target_key]
    history.append(now)


    #清理超过时间窗口的旧记录
    while history and now - history[0] > SYN_FLOOD_WINDOW:
        history.popleft()

    #如果队列长度超过阈值，触发警报
    if len(history) >= SYN_FLOOD_THRESHOLD:
        alert_data = {
            "timestamp":datetime.now().isoformat(),
            "alert_type":"SYN_FLOOD",
            "source_ip":src_ip,
            "target_ip":dst_ip,
            "target_port":dst_port,
            "packet_count": len(history),
        }

        alert_text = Text()
        alert_text.append("目标 IP:",style="bold white")
        alert_text.append(f"{dst_ip}:{dst_port}\n",style="bold red")
        alert_text.append("行为:",style="bold white")
        alert_text.append(f"在{SYN_FLOOD_WINDOW}秒内收到了{len(history)}个 SYN 包\n",style="bold yellow")
        alert_text.append("最近源 IP:",style="bold white")
        alert_text.append(f"{src_ip}\n",style="bold red")
        console.print(Panel(
            alert_text,
            title="[bold red blink]警报:检测到 SYN FLOOD 洪水攻击[/bold red blink]",
            border_style="red",
            expand=False
        ))

        with open("alerts.log","a",encoding="utf-8") as f:
            f.write(json.dumps(alert_data,ensure_ascii=False) + "\n")
        history.clear()

def analyze_packet(pkt):
    global packet_count
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    packet_count += 1
    
    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    src_ip = ip_layer.src
    dst_port = tcp_layer.dport
    
    # 只检测 SYN 包
    if tcp_layer.flags == 'S':
        dst_ip = ip_layer.dst
        check_port_scan(src_ip, dst_port)
        check_syn_flood(src_ip,dst_ip,dst_port)

if __name__ == "__main__":
    print_startup_banner()
    try:
        # 增加一个非常弱的过滤条件，减轻 CPU 负担
        sniff(prn=analyze_packet, store=False, filter="tcp")
    except KeyboardInterrupt:
        # 优雅地处理 Ctrl+C 退出
        summary = Table(title="[bold cyan]📊 本次运行统计[/bold cyan]", show_header=False)
        summary.add_row("总共抓取包数", f"[green]{packet_count}[/green]")
        summary.add_row("告警触发次数", f"[red]{len(open('alerts.log').readlines()) if __import__('os').path.exists('alerts.log') else 0}[/red]")
        console.print(summary)
        console.print("[bold yellow]👋 IDS 已安全退出[/bold yellow]")