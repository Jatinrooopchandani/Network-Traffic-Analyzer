from scapy.all import *

def packet_capture(interface, count):
    # Sniff packets from the specified interface
    packets = sniff(iface=interface, count=count)
    return packets

# Capture packets from the specified interface (replace 'your wifi/ethernet interface name here' with the actual interface name)
captured_packets = packet_capture('eth0', 10)

def traffic_logging(packets, logfile):
    # Log captured packets to the specified log file
    with open(logfile, 'w') as f:
        for packet in packets:
            f.write(str(packet) + '\n')  # Write each packet to the file

# Log captured packets to a file named 'network_traffic.log' (you can change the file name if desired)
log_file_path = 'network_traffic.log'
traffic_logging(captured_packets, log_file_path)

# Print a message confirming the logging operation
print(f'Traffic logged to {log_file_path}')
