from scapy.all import *

def packet_capture(interface, count):
    packets = sniff(iface=interface, count=count)
    return packets

interface_name = 'eth0'
captured_packets = packet_capture(interface_name, 10)


for packet in captured_packets:
    print(packet.summary())
