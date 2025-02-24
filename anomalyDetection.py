from scapy.all import *

def packet_capture(interface, count):
    """Capture network packets from a specified interface.
    
    Args:
        interface (str): The network interface to capture packets from.
        count (int): The number of packets to capture.
    
    Returns:
        list: A list of captured packets.
    """
    packets = sniff(iface=interface, count=count)
    return packets

def anomaly_detection(packets, threshold):
    """Detects anomalies in network packets based on packet length.
    
    Args:
        packets (list): A list of network packets to analyze.
        threshold (int): The maximum allowed packet length before considering it an anomaly.
    
    Returns:
        list: A list of anomalous packets as strings.
    
    Prints:
        Packet Length: <length> for each packet analyzed.
    """
    anomalies = []
    for packet in packets:
        packet_length = len(packet)
        print(f"Packet Length: {packet_length}")
        if packet_length > threshold:
            anomalies.append(str(packet))
    return anomalies


wifi_interface = 'eth0'
captured_packets = packet_capture(wifi_interface, 100) 

threshold_size = 1500 
detected_anomalies = anomaly_detection(captured_packets, threshold_size)

print(f"Total packets captured: {len(captured_packets)}")
print(f"Anomalies detected: {len(detected_anomalies)}")

for anomaly in detected_anomalies:
    print(anomaly)
