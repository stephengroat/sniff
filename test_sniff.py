import unittest
import os
import sys
import scapy.all as scapy
import scapy_http.http as shttp
import time
import threading
import re
import random
import copy
sys.path.insert(
        0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
        )
import sniff  # noqa


def test_alert(capsys):
    sniffer = sniff.Sniff(alertsection='test.com/test', alertsize=2, attl=2)
    pkt = shttp.HTTP()
    pkt = pkt/shttp.HTTPRequest(Host="test.com", Path="/test")
    for x in range(0, 3):
        sniffer.pkt(pkt)
    captured = capsys.readouterr().out
    assert re.match(
            r'High traffic generated an alert - hits = 3, triggered at .*\n',
            captured)
    time.sleep(1)
    sniffer.pkt(pkt)
    time.sleep(3)
    captured = capsys.readouterr().out
    assert re.match(
            r'High traffic resolved an alert - hits = 0, triggered at .*\n',
            captured)


def test_summary(capsys):
    sniffer = sniff.Sniff()
    timerThread = threading.Thread(target=sniffer.summary)
    timerThread.start()
    time.sleep(2)
    sniffer.cache[random.randint(0, sniffer.cache.maxsize)] = "www.test.com"
    time.sleep(10)
    captured = copy.deepcopy(capsys.readouterr().out)
    sniffer.summary_run.clear()
    assert re.match(
            r'(Summary\nSite: # of hits\nwww.test.com: 1\nTotal hits: 1 Hits per second: 0.1\n)',  # noqa
            captured)


if __name__ == '__main__':
    unittest.main()
