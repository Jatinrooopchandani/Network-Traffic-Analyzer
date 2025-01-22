from scapy.all import *

def packet_capture(interface, count):
    packets = sniff(iface=interface, count=count)
    return packets

def anomaly_detection(packets, threshold):
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
