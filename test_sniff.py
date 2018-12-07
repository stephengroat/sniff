import unittest
import os
import sys
import scapy.all as scapy
import scapy_http.http
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
import sniff

class TestSniff(unittest.TestCase):

    def test_upper(self):
        self.sniff = sniff.Sniff(alert='test.com', attl=5)
        self.sniff.pkt(scapy_http.http.HTTP()/scapy_http.http.HTTPRequest(Host="test.com",Path=""))
        self.sniff.pkt(scapy_http.http.HTTP()/scapy_http.http.HTTPRequest(Host="test.com",Path=""))
        self.sniff.pkt(scapy_http.http.HTTP()/scapy_http.http.HTTPRequest(Host="test.com",Path=""))
        time.sleep(1)


if __name__ == '__main__':
    unittest.main()
