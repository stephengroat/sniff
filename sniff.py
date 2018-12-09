#!/usr/bin/python
# regex
import re
# packet sniffing and decoding
import scapy.all as scapy
import scapy_http.http as shttp
# cache
from cachetools import TTLCache
import random
# threading
import threading
import time
import datetime
# Counting caches
from collections import Counter
import argparse
# For capturing SIGINT
import signal
import sys


class Sniff:
    # check if alert still valid and, if not, turn off
    def alert(self):
        if self.__alerted:
            hits = list(self.alert.values()).count(self.alertSection)
            if hits <= self.alertSize:
                print('High traffic resolved an alert - hits = ' +
                      str(hits) +
                      ', triggered at ' +
                      str(datetime.datetime.now()))
                self.__alerted = False

    # loop to print summary every 10 seconds
    def summary(self):
        next_call = time.time()
        while True:
            print(datetime.datetime.now())
            if self.cache.currsize != 0:
                print("Summary: SITE/HITS")
                for site in Counter(list(self.cache.values())).most_common():
                    print(site)
            # prevent drift by taking summary runtime into account
            next_call = next_call+self.cache.ttl
            time.sleep(next_call - time.time())

    # thread to trigger alert cache experation
    def expire(self):
        # trigger experation on signal or timeout
        self.e.wait(timeout=self.alert.ttl)
        self.alert.expire()

    def pkt(self, pkt):
        if shttp.HTTPRequest in pkt:
            # get website section
            host = pkt['HTTPRequest'].Host.decode("utf-8")
            pathre = r'^((\/\w+)\/?)'
            matches = re.match(pathre, pkt['HTTPRequest'].Path.decode("utf-8"))
            if matches:
                host += matches.group(2)

            # add entries to both caches
            self.cache[random.randint(0, self.cache.maxsize)] = host
            self.alert[random.randint(0, self.alert.maxsize)] = host

            # TODO @stephengroat parameterize out alert value with argparse
            if host == self.alertSection:
                hits = list(self.alert.values()).count(self.alertSection)
                if hits > self.alertSize:
                    # if not alerted, activate
                    if not self.__alerted:
                        print('High traffic generated an alert - hits = ' +
                              str(hits) +
                              ', triggered at ' +
                              str(datetime.datetime.now()))
                        self.__alerted = True
                    # if alerted, kill existing expire thread
                    elif self.__alerted:
                        self.e.set()
                        self.e.clear()
                    # start expire thread
                    expireThread = threading.Thread(target=self.expire)
                    expireThread.start()

    def signal_handler(self, sig, frame):
        print('Exiting')
        self.e.set()
        sys.exit(0)

    def __init__(self, alertsection=None, alertsize=0, maxcachesize=1024,
                 cttl=10, attl=120):
        self.__alerted = False
        self.cache = TTLCache(maxsize=maxcachesize, ttl=cttl)
        self.alert = TTLCache(maxsize=maxcachesize, ttl=attl, cb=self.alert)
        self.alertSection = alertsection
        self.alertSize = alertsize
        self.e = threading.Event()
        signal.signal(signal.SIGINT, self.signal_handler)

    def __call__(self):
        # start summary thread
        timerThread = threading.Thread(target=self.summary)
        timerThread.daemon = True
        timerThread.start()
        # only look at tcp based http traffic to and from port 80 for speed
        filter = "(tcp and dst port 80) or (tcp and src port 80)"
        scapy.sniff(filter=filter, prn=self.pkt)


if __name__ == '__main__':
    parse = argparse.ArgumentParser(
            description='Sniff HTTP traffic for sections and alert'
            )
    parse.add_argument(
            '--alertsection', type=str, required=True,
            help='website section for alert (i.e. test.com/test or test.com'
            )
    parse.add_argument(
            '--alertsize', type=int, required=True,
            help='number of hits within 2 minutes to generate alert'
            )
    args = parse.parse_args()
    sniffer = Sniff(alertsection=args.alertsection, alertsize=args.alertsize)
    sniffer()
