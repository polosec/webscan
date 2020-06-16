#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2020/5/25 17:44
# @Author  : PoLoSec.
# @File    : quickscan.py
# @Software: PyCharm
import time
import argparse
from Scan import  Scanner
import  re
def getIp(domain):
    import socket
    myaddr = socket.getaddrinfo(domain,'http')[0][4][0]
    return  myaddr
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('url')
    parser.add_argument('-d',dest='delay',type=float,default=0)
    parser.add_argument('-t',dest='threadnum',default=10,type=int)
    parser.add_argument('-p',dest='pl',default=0,type=int)
    args=parser.parse_args()
    if args.pl==1:
        scan=Scanner(args)
        scan.Ms(args.url)
    else:
        urls=re.split(',',args.url)#这是待进行解析的URL
        ips=list()

        for url in urls:
            ipaddr=getIp(url)
            ips.append(ipaddr)
        ips=','.join(ips)#解析后的IP地址，通过","连接
        scanner=Scanner(args)
        scanner.Ms(ips)
if __name__=='__main__':
    b=time.time()
    main()
    f=time.time()
    print("任务执行完成，总用时%.2f秒"%(f-b))