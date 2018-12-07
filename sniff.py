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

class Sniff
    def __init__(self):
        self.__alerted = False
        self.cache = TTLCache(maxsize=1024, ttl=10)
        self.alert = TTLCache(maxsize=1024, ttl=21, cb=self.__alert)
        
    def alert(self):
        if self.__alerted and list(self.alert.values()).count('pagead2.googlesyndication.com/pagead') <= 2:
            print('ALERT OFF')
            self.__alerted = False
            
    def summary():
        next_call = time.time()
        while True:
            print(Counter(list(self.cache.values())))
            next_call = next_call+10
            time.sleep(next_call - time.time())


    def pkt(self, pkt):
        if scapy_http.http.HTTPRequest in pkt:
            host = pkt['HTTPRequest'].Host.decode("utf-8")
            path_re = r'^((\/\w+)\/?)'
            matches = re.match(path_re, pkt['HTTPRequest'].Path.decode("utf-8"))
            if matches:
                self.cache[random.randint(0, self.cache.maxsize)] = host + matches[2]
                self.alert[random.randint(0, self.alert.maxsize)] = host + matches[2]
            else:
                self.cache[random.randint(0, self.cache.maxsize)] = host
                self.alert[random.randint(0, self.alert.maxsize)] = host
            # TODO @stephengroat parameterize out alert value with argparse
            if not self.__alerted and list(self.alert.values()).count('pagead2.googlesyndication.com/pagead') > 2:
                # TODO @stephengroat start a timer to make sure that expire is triggered
                print('ALERT ON')
                self.__alerted = True
                
    def __call__(self):
        # start summary thread
        timerThread = threading.Thread(target=self.summary)
        timerThread.daemon = True
        timerThread.start()
        # only look at tcp based http traffic to and from port 80 for speed
        filter = "(tcp and dst port 80) or (tcp and src port 80)"
        scapy.sniff(filter=filter, prn=self.pkt)

if __name__ == '__main__':
    sniffer = Sniff()
    sniffer()
