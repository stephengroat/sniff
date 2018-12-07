#!/usr/bin/python
# regex
import re
# packet sniffing and decoding
import scapy.all as scapy
import scapy_http.http
# cache
from cachetools import TTLCache
import random
# threading
import threading
import time
# Counting caches
from collections import Counter

alerted = False

def alert():
    global alerted
    if alerted and list(alert.values()).count('pagead2.googlesyndication.com/pagead') <= 2:
        print('ALERT OFF')
        alerted = False


cache = TTLCache(maxsize=1024, ttl=10)
alert = TTLCache(maxsize=1024, ttl=21, cb=alert)


def summary():
    next_call = time.time()
    while True:
        print(Counter(list(cache.values())))
        next_call = next_call+10
        time.sleep(next_call - time.time())


def pkt(pkt):
    global alerted
    if scapy_http.http.HTTPRequest in pkt:
        host = pkt['HTTPRequest'].Host.decode("utf-8")
        path_re = r'^((\/\w+)\/?)'
        matches = re.match(path_re, pkt['HTTPRequest'].Path.decode("utf-8"))
        if matches:
            cache[random.randint(0, cache.maxsize)] = host + matches[2]
            alert[random.randint(0, alert.maxsize)] = host + matches[2]
        else:
            cache[random.randint(0, cache.maxsize)] = host
            alert[random.randint(0, alert.maxsize)] = host
        if not alerted and list(alert.values()).count('pagead2.googlesyndication.com/pagead') > 2:
            print('ALERT ON')
            alerted = True


if __name__ == '__main__':
    # start summary thread
    timerThread = threading.Thread(target=summary)
    timerThread.daemon = True
    timerThread.start()
    # only look at tcp based http traffic to and from port 80 for speed
    filter = "(tcp and dst port 80) or (tcp and src port 80)"
    scapy.sniff(filter=filter, prn=pkt)
