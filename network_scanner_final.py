import scapy.all as scapy
import pprint

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    bcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_bcast = bcast/arp_request
    answered_list = scapy.srp(arp_request_bcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\n----------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)


scan("192.168.1.1/24")