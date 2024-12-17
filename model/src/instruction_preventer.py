import pickle
from traffic_sniffer import process_packet
from scapy.all import sniff

with open("../models/anomaly_detector.pkl", "rb") as f:
    anomaly_detector = pickle.load(f)

with open("../models/attack_classifier.pkl", "rb") as f:
    attack_classifier = pickle.load(f)

def analyze_packet(packet_details):
    try:
        features = [[packet_details["size"], packet_details["protocol"]]]

        anomaly_score = anomaly_detector.predict(features)[0]
        if anomaly_score == -1: 
            print(f"Anomaly detected: {packet_details}")
            return "Blocked"

        attack_type = attack_classifier.predict(features)[0]
        print(f"Attack classified: {attack_type}")
        return attack_type
    except Exception as e:
        print(f"Error analyzing packet: {e}")
        return None

def start_intrusion_prevention(interface="eth0"):
    print(f"Starting Intrusion Prevention System on interface {interface}...")

    def process_and_analyze(packet):
        packet_details = process_packet(packet)
        if packet_details:
            result = analyze_packet(packet_details)
            if result == "Blocked":
                print("Threat mitigated: Packet dropped.")
            else:
                print(f"Packet classified as: {result}")

    try:
        sniff(iface=interface, store=False, prn=process_and_analyze)
    except Exception as e:
        print(f"Error starting IPS: {e}")

if __name__ == "__main__":
    start_intrusion_prevention(interface="eth0")
