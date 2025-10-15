import socket
import threading
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 常见端口服务映射
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB"
}

def resolve_target(target):
    """解析目标，将域名转换为IP地址"""
    try:
        # 如果是IP地址，直接返回
        socket.inet_aton(target)
        return target
    except socket.error:
        # 如果是域名，解析为IP
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] 解析域名: {target} -> {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] 无法解析域名: {target}")
            return None

def get_service_banner(ip, port, timeout=3):
    """尝试获取服务banner信息"""
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        
        # 尝试接收banner信息
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner if banner else "No banner"
    except:
        return "No banner"

def scan_port(target_ip, port, timeout=2, show_banner=False):
    """扫描单个端口"""
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((target_ip, port))
        s.close()
        
        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = ""
            if show_banner:
                banner = get_service_banner(target_ip, port)
            return port, service, banner
        else:
            return None
    except Exception as e:
        return None

def port_range(port_str):
    """解析端口范围字符串"""
    ports = set()
    parts = port_str.split(',')
    
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    ports.update(range(start_port, end_port + 1))
                else:
                    raise ValueError("端口范围无效")
            except ValueError:
                raise argparse.ArgumentTypeError(f"无效的端口范围: {part}")
        else:
            try:
                port = int(part.strip())
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    raise ValueError("端口号超出范围")
            except ValueError:
                raise argparse.ArgumentTypeTypeError(f"无效的端口号: {part}")
    
    return sorted(ports)

def scan_target(target, ports, threads=50, timeout=2, show_banner=False):
    """扫描目标的所有指定端口"""
    target_ip = resolve_target(target)
    if not target_ip:
        return []
    
    print(f"[+] 开始扫描 {target} ({target_ip})")
    print(f"[+] 扫描端口: {len(ports)} 个")
    print(f"[+] 线程数: {threads}")
    print("-" * 60)
    
    open_ports = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # 提交所有扫描任务
        future_to_port = {
            executor.submit(scan_port, target_ip, port, timeout, show_banner): port 
            for port in ports
        }
        
        # 处理完成的任务
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                port, service, banner = result
                status = f"{port}/tcp 开放 - {service}"
                if banner and show_banner:
                    status += f" | {banner}"
                print(f"[+] {status}")
                open_ports.append(result)
    
    end_time = time.time()
    print("-" * 60)
    print(f"[+] 扫描完成! 耗时: {end_time - start_time:.2f} 秒")
    print(f"[+] 发现 {len(open_ports)} 个开放端口")
    
    return open_ports

def display_help():
    """显示帮助信息"""
    help_text = """
端口扫描器使用说明:

基本用法:
  python port_scanner.py -t 目标 [-p 端口] [-T 线程] [选项]

参数说明:
  -t, --target    目标IP或域名 (必需)
  -p, --ports     端口范围 (默认: 1-1000)
                  示例: 80,443,8080 或 1-100 或 22,80-100,443
  -T, --threads   线程数 (默认: 50)
  --timeout   超时时间(秒) (默认: 2)
  -b, --banner    显示服务banner信息
  --top-ports     扫描最常见的N个端口
  -v, --verbose   显示详细信息

示例:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t example.com -p 80,443,22,21
  python port_scanner.py -t 192.168.1.1 -p 1-1000 -T 100 -b
  python port_scanner.py -t 10.0.0.1 --top-ports 100

常见端口列表:
  21-FTP, 22-SSH, 23-Telnet, 25-SMTP, 53-DNS, 80-HTTP, 110-POP3
  143-IMAP, 443-HTTPS, 445-SMB, 993-IMAPS, 995-POP3S, 1433-MSSQL
  3306-MySQL, 3389-RDP, 5432-PostgreSQL, 6379-Redis
    """
    print(help_text)

def get_top_ports(count):
    """获取最常见的端口列表"""
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ]
    # 如果需要的端口数超过预定义的，添加一些其他常见端口
    if count > len(common_ports):
        additional_ports = [
            587, 993, 995, 1433, 1521, 1723, 2222, 2375, 2376, 3000,
            5432, 6379, 7474, 7687, 8000, 8008, 8081, 8443, 8888, 9000,
            9200, 9300, 11211, 27017, 50000
        ]
        common_ports.extend(additional_ports)
    
    return common_ports[:count]

def main():
    parser = argparse.ArgumentParser(description='端口扫描器', add_help=False)
    
    parser.add_argument('-t', '--target', help='目标IP或域名')
    parser.add_argument('-p', '--ports', default='1-1000', help='端口范围 (默认: 1-1000)')
    parser.add_argument('-T', '--threads', type=int, default=50, help='线程数 (默认: 50)')
    parser.add_argument('--timeout', type=float, default=2, help='超时时间(秒) (默认: 2)')
    parser.add_argument('-b', '--banner', action='store_true', help='显示服务banner信息')
    parser.add_argument('--top-ports', type=int, help='扫描最常见的N个端口')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('-h', '--help', action='store_true', help='显示帮助信息')
    
    # 如果没有参数，显示帮助
    if len(sys.argv) == 1:
        display_help()
        return
    
    args = parser.parse_args()
    
    if args.help:
        display_help()
        return
    
    if not args.target:
        print("[-] 错误: 必须指定目标 (-t/--target)")
        print("使用 -h 查看帮助信息")
        return
    
    try:
        # 确定要扫描的端口
        if args.top_ports:
            ports_to_scan = get_top_ports(args.top_ports)
            print(f"[+] 扫描最常见的 {args.top_ports} 个端口")
        else:
            ports_to_scan = port_range(args.ports)
        
        # 执行扫描
        open_ports = scan_target(
            target=args.target,
            ports=ports_to_scan,
            threads=args.threads,
            timeout=args.timeout,
            show_banner=args.banner
        )
        
        # 显示汇总信息
        if open_ports:
            print("\n[+] 开放端口汇总:")
            for port, service, banner in open_ports:
                info = f"  {port}/tcp - {service}"
                if banner and args.banner:
                    info += f" | {banner}"
                print(info)
        
    except KeyboardInterrupt:
        print("\n[-] 用户中断扫描")
    except Exception as e:
        print(f"[-] 错误: {e}")

if __name__ == "__main__":
    main()
