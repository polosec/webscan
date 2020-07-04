#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2020/5/25 22:13
# @Author  : PoLoSec.
# @File    : Scan.py
# @Software: PyCharm
import json
import  nmap
import os
import threading
nm=nmap.PortScanner()

class Scanner():
    def __init__(self,args):
        self.delay=args.delay
        self.threadnum=args.threadnum
        self.url=args.url
        self.thread_max = threading.BoundedSemaphore(self.threadnum)
        self.threads=[]
    def Ms(self,ip):
        if os.path.exists('res.json'):
            os.remove('res.json')
        cmd = " masscan.exe " + ip + " -p 1-10000 -oJ res.json --rate 10000"
        os.system(cmd)
        with open('res.json', 'r') as f:
            data = json.load(f)
            lenth = len(data)
            for i in range(lenth):
                ip = data[i]['ip']
                port = data[i]['ports'][0]['port']  # 拿到开放端口号
                self.thread_max.acquire()
                t = threading.Thread(target=self.nmapscan, args=(ip, port))
                self.threads.append(t)
                t.start()
            for t in self.threads:
                t.join()
    def save(self,strings):

        with open(self.url+'.txt','a') as f1:
            f1.write(str(strings))
            f1.close()
    def nmapscan(self,host, port):
        res = nm.scan(host, arguments='-sV -p' + str(
            port) + ' -script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36"')
        for host, result in res['scan'].items():
            if (result['status']['state'] == 'up'):
                try:
                    for port in result['tcp']:
                        try:
                            strings='Host :%s TCP Port:%s,Status:%s,Name:%s,Product:%s.\n' % (
                            host,port, result['tcp'][port]['state'], result['tcp'][port]['name'],
                            result['tcp'][port]['product'])
                            print(strings)
                            self.save(strings)
                        except:
                            pass
                except:
                    pass
                try:
                    for port in result['udp']:
                        try:
                            print('UDP Port:%s,Status:%s,Name:%s,Product:%s.' % (
                            port, result['udp'][port]['state'], result['udp'][port]['name'],
                            result['udp'][port]['product']))
                        except:
                            pass
                except:
                    pass
        self.thread_max.release()
