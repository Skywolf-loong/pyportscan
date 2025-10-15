# pyportscan
python开发的端口扫描工具

功能特性
多目标支持：支持IP地址和域名扫描

灵活的端口指定：

单个端口：-p 80

端口范围：-p 1-1000

多个端口：-p 22,80,443,8080

混合格式：-p 22,80-100,443,8000-8080

常见端口：--top-ports 100

服务识别：

内置常见端口服务映射

可选的banner信息获取

自动识别服务类型

高性能：

多线程扫描

可配置线程数

连接超时控制


# 显示帮助
python port_scanner.py -h

# 基本扫描
python port_scanner.py -t 192.168.1.1

# 扫描指定端口
python port_scanner.py -t example.com -p 80,443,22

# 扫描端口范围
python port_scanner.py -t 192.168.1.1 -p 1-1000 -T 100

# 显示banner信息
python port_scanner.py -t 10.0.0.1 -p 21,22,80 -b

# 扫描最常见端口
python port_scanner.py -t target.com --top-ports 50
