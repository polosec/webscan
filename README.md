# webscan
nmap+masscan扫描器
## 这是一款nmap+masscan的互联网端口与服务扫描器
## 适用于CTF的目录扫描器，支持自定义关键字 如 flag，xxxctf。
## 使用方法：python quickscan.py url/ip
## 特点：线程可以自定义，masscan速度默认较快，如有需要可以自己调整；使用masscan快速发现端口，将发现的端口给nmap进行精准服务探测。
## 使用生产者-消费者模型进行多线程控制
## 面向对象思想:)
