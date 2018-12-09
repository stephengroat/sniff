import unittest
import os
import sys
import scapy.all as scapy
import scapy_http.http as shttp
import time
import re
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
    captured = capsys.readouterr()
    assert re.match(
            r'High traffic generated an alert - hits = 3, triggered at .*\n',
            captured.out)
    time.sleep(1)
    sniffer.pkt(pkt)
    time.sleep(3)
    captured = capsys.readouterr()
    assert re.match(
            r'High traffic resolved an alert - hits = 0, triggered at .*\n',
            captured.out)


if __name__ == '__main__':
    unittest.main()
