import unittest
import os
import sys
import scapy.all as scapy
import scapy_http.http as shttp
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
import sniff

def test_alert(capsys):
    sniffer = sniff.Sniff(alert='test.com/test', attl=2)
    pkt = shttp.HTTP()
    pkt = pkt/shttp.HTTPRequest(Host="test.com",Path="/test")
    for x in range(0,3):
        sniffer.pkt(pkt)
    captured = capsys.readouterr()
    assert captured.out == "ALERT ON\n"
    time.sleep(1)
    sniffer.pkt(pkt)
    time.sleep(3)
    captured = capsys.readouterr()
    assert captured.out == "ALERT OFF\n"


if __name__ == '__main__':
    unittest.main()
