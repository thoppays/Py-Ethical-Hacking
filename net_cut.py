#!/usr/bin/env python

# Try from the Linux machine
# Run the linux command first - iptables -I FORWARD -j NFQUEUE --queue-num 0
# When done, run - iptables --flush

import netfilterqueue

def process_packet(packet):
    print(packet.get_payload())
    packet.accept()     # forwards the packet to the remote computer
    # packet.drop()

queue =  netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

