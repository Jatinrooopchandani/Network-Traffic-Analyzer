from scapy.all import *

def packet_capture(interface, count):
    """Capture network packets from a specified interface.
    
    Args:
        interface (str): The name of the network interface to capture packets from.
        count (int): The number of packets to capture before stopping.
    
    Returns:
        list: A list of captured packets, where each packet is a scapy Packet object.
    """
    packets = sniff(iface=interface, count=count)
    return packets

interface_name = 'eth0'
captured_packets = packet_capture(interface_name, 10)


for packet in captured_packets:
    print(packet.summary())
