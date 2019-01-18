import scapy.all as scapy
import pprint

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    bcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_bcast = bcast/arp_request
    # answered_list, unanswered_list = scapy.srp(arp_request_bcast, timeout=1)
    answered_list = scapy.srp(arp_request_bcast, timeout=1)[0]

    # print(answered_list.summary())
    for element in answered_list:
        # print(element)
        print(element[1].psrc)
        print(element[1].hwsrc)
        print("--------------------")


scan("192.168.1.1/24")