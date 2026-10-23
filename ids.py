import json
import os
from scapy.all import sniff,IP,TCP
from datetime import datetime
import time
from collections import defaultdict


#======= 状态管理 =======
#记录每个源IP的扫描历史：{"192.168.1.5":[(时间戳,端口),...]}
scan_history = defaultdict(list)

#触发警告的阈值
TIME_WINDOW = 5         #5秒内
PORT_THRESHOLD = 10     #访问超过10个不同端口


def check_port_scan(src_ip,dst_port):
    #检查是否发生端口扫描
    now = time.time()

    #把访问记录下来
    scan_history[src_ip].append((now,dst_port))

    #清理过期的历史记录
    scan_history[src_ip] = [
        (t,p)for t,p in scan_history[src_ip]
        if now - t <= TIME_WINDOW
    ]

    #统计这段时间内访问了多少个“不同”的端口
    unique_ports = set(p for t,p in scan_history[src_ip])


    if len(unique_ports) >= PORT_THRESHOLD:

        #构造告警数据
        alert_data = {
            "timestamp":datetime.now().isoformat(),
            "alert_type":"PORT_SCAN",
            "source_ip":src_ip,
            "port_count":len(unique_ports),
            "duration_seconds":TIME_WINDOW
        }

        #终端打印红色高亮
        print(f"\n\033[91m[警报] 检测到端口扫描！\033[0m")
        print(f"\033[91m源 IP:{src_ip} | 在{TIME_WINDOW}秒内扫描了{len(unique_ports)}个端口\033[0m\n")

        #写入 json 文件
        with open("alerts.log","a",encoding="utf-8")as f:
            f.write(json.dumps(alert_data,ensure_ascii=False) + "\n")

        #清空记录，防止同一次扫描疯狂报警
        scan_history[src_ip] = []



# =========核心抓包逻辑=========
def analyze_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return


    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    src_ip = ip_layer.src
    dst_port = tcp_layer.dport

    #只检测 SYN 包(TCP 三次握手的第一次，扫描器最常用)
    if tcp_layer.flags == 'S':
        #调用检测函数
        check_port_scan(src_ip,dst_port)



if __name__ == "__main__":
    print("[*] 正在监听网络流量(按 Ctrl+C 停止)")
    print(f"[*] 规则加载:{TIME_WINDOW}秒内扫描超过{PORT_THRESHOLD}个端口触发告警")
    #只抓 TCP 包，减少资源消耗
    sniff(prn=analyze_packet,store=False,filter="tcp")