#!/usr/bin/python
import re
import scapy.all as scapy
import scapy_http.http
from cachetools import cached, TTLCache
import random

cache = TTLCache(maxsize=1024, ttl=10)

def pkt(pkt):
    if scapy_http.http.HTTPRequest in pkt:
        matches = re.match('^((\/\w+)\/?)', pkt['HTTPRequest'].Path.decode("utf-8"))
        if matches:
            print(pkt['HTTPRequest'].Host.decode("utf-8") + matches[2])
            cache[random.randint(0,1024)] = pkt['HTTPRequest'].Host.decode("utf-8") + matches[2]
        else:
            print(pkt['HTTPRequest'].Host.decode("utf-8"))
            cache[random.randint(0,1024)] = pkt['HTTPRequest'].Host.decode("utf-8")
        print(cache.currsize)

if __name__ == '__main__':
    scapy.sniff(filter="(tcp and dst port 80) or (tcp and src port 80)", prn=pkt)
