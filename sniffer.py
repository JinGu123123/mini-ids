from scapy.all import sniff,IP,TCP,UDP,ICMP
from datetime import datetime


def analyze_packet(pkt):

    #过滤掉非IP包（如APP广播包）
    if not pkt.haslayer(IP):
        return;

    #获取基础信息
    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto
    time_str = datetime.now().strftime("%H:%M:%S")

    proto_name = "OTHER"
    src_port = "-"
    dst_port = "-"


    #解析传输层（TCP/UDP）
    if pkt.haslayer(TCP):
        proto_name = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport

    elif pkt.haslayer(UDP):
        proto_name = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    elif pkt.haslayer(TCP):
        proto_name = "ICMP"
        #ICMP没有端口,打印类型(8=请求,0=回复)
        src_port = "type:" + str(pkt[ICMP].type)
        dst_port = "-"


    #打印格式化输出
    if proto_name in ["TCP","UDP","ICMP"]:
        print(f"[{time_str}]{proto_name:5s} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


if __name__ == "__main__":
    print("[*]正在监听网络流量(按Ctrl+C 停止)...")

    #store=False 表示不把抓到的包保存到内存,防止内存爆满
    sniff(prn=analyze_packet,store=False,filter="ip")