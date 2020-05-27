#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2020/5/21 10:11
# @Author  : PoLoSec.
# @File    : webscan.py
# @Software: PyCharm
import  nmap
import user_agent
nm=nmap.PortScanner()
headers = {"User-Agent": "" + user_agent.generate_user_agent() + ""}
def protscan(host,port):
    nm.scan('host','1-443',arguments='-sS')
    for host in nm.all_hosts():
        print('Host %s (%s)'%(host,nm[host].hostname()))
        print('State: %s'%nm[host].state())
        for proto in nm[host].all_protocols():
            print('protocol:%s'%proto)
            openport=nm[host][proto].keys()
            for port in openport:
                print('port :%s \t state:%s'%(port,nm[host][proto][port]['state']))
def isalive(host):
    nm.scan(host,arguments='-sP')
    hostlist=[(x,nm[x]['status']['state']) for x in nm.all_hosts()]
    print(nm.all_hosts())
    for host,state in hostlist:
        print("host: %s is %s"%(host,state))
#isalive('192.168.1.37')
def detect(host,port):
    res=nm.scan(host,arguments='-sV -p'+str(port))
    # for host,result in res['scan'].items():
    #     if (result['status']['state']=='up'):
    #         print("Host:%s ,OS Detect:"%host)
    #         for os in result['osmatch']:
    #             print('OS:%s,accuracy:%s'%(os['name'],os['accuracy']))
    #         try:
    #             for port in result['tcp']:
    #                 try:
    #                     print('TCP Port:%s,Status:%s,Name:%s,Product:%s.'%(port,result['tcp'][port]['state'],result['tcp'][port]['name'],result['tcp'][port]['product']))
    #                 except:pass
    #         except:pass
    #         try:
    #             for port in result['udp']:
    #                 try:
    #                     print('UDP Port:%s,Status:%s,Name:%s,Product:%s.' % ( port, result['udp'][port]['state'], result['udp'][port]['name'],result['udp'][port]['product']))
    #                 except:
    #                     pass
    #         except:
    #             pass

detect('58.87.64.85',8888)