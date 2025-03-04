from scapy.all import *

def packet_capture(interface, count):
    # Sniff packets from the specified interface
    """Capture network packets from a specified interface.
    
    Args:
        interface (str): The network interface to capture packets from.
        count (int): The number of packets to capture.
    
    Returns:
        list: A list of captured packet objects.
    """
    packets = sniff(iface=interface, count=count)
    return packets

# Capture packets from the specified interface (replace 'your wifi/ethernet interface name here' with the actual interface name)
captured_packets = packet_capture('eth0', 10)

def traffic_logging(packets, logfile):
    # Log captured packets to the specified log file
    """Logs captured network packets to a specified log file.
    
    Args:
        packets (list): A list of captured network packets to be logged.
        logfile (str): The path to the file where the packets will be logged.
    
    Returns:
        None: This function does not return any value.
    
    Raises:
        IOError: If there is an issue opening or writing to the log file.
    """
    with open(logfile, 'w') as f:
        for packet in packets:
            f.write(str(packet) + '\n')  # Write each packet to the file

# Log captured packets to a file named 'network_traffic.log' (you can change the file name if desired)
log_file_path = 'network_traffic.log'
traffic_logging(captured_packets, log_file_path)

# Print a message confirming the logging operation
print(f'Traffic logged to {log_file_path}')
