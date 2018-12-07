#!/usr/bin/python
import re
import scapy.all as scapy
import scapy_http.http
from cachetools import TTLCache
import random
import datetime
import threading
import time


def alert():
    print("Hello")


cache = TTLCache(maxsize=1024, ttl=10)
alert = TTLCache(maxsize=1024, ttl=21, cb=alert)

def summary():
    next_call = time.time()
    while True:
        print(cache.values)
        next_call = next_call+10
        time.sleep(next_call - time.time())


def pkt(pkt):
    if scapy_http.http.HTTPRequest in pkt:
        host = pkt['HTTPRequest'].Host.decode("utf-8")
        path_re = r'^((\/\w+)\/?)'
        matches = re.match(path_re, pkt['HTTPRequest'].Path.decode("utf-8"))
        if matches:
            # print(host + matches[2])
            cache[random.randint(0, cache.maxsize)] = host + matches[2]
            alert[random.randint(0, alert.maxsize)] = host + matches[2]
        else:
            # print(host)
            cache[random.randint(0, cache.maxsize)] = host
            alert[random.randint(0, alert.maxsize)] = host


if __name__ == '__main__':
    timerThread = threading.Thread(target=summary)
    timerThread.daemon = True
    timerThread.start()
    filter = "(tcp and dst port 80) or (tcp and src port 80)"
    scapy.sniff(filter=filter, prn=pkt)
