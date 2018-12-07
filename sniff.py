#!/usr/bin/python
import re
import scapy.all as scapy
import scapy_http.http

def pkt(pkt):
    if scapy_http.http.HTTPRequest in pkt:
        matches = re.match('^((\/\w+)\/?)', pkt['HTTPRequest'].Path.decode("utf-8"))
        if matches:
            print(pkt['HTTPRequest'].Host.decode("utf-8") + matches[2])
        else:
            print(pkt['HTTPRequest'].Host.decode("utf-8"))

if __name__ == '__main__':
    scapy.sniff(filter="(tcp and dst port 80) or (tcp and src port 80)", prn=pkt)
