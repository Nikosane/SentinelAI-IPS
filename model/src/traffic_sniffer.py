import scapy.all as scapy
import logging

# Set up logging
logging.basicConfig(
    filename="../logs/traffic_sniffer.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def process_packet(packet):
    """
    Processes a captured packet to extract relevant features.
    """
    try:
        # Log packet details
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            size = len(packet)
            logging.info(f"Packet: Src: {src_ip}, Dst: {dst_ip}, Proto: {protocol}, Size: {size}")
            print(f"Captured Packet: Src: {src_ip}, Dst: {dst_ip}, Proto: {protocol}, Size: {size}")

            # Return packet details as a dictionary
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "size": size,
            }
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        print(f"Error processing packet: {e}")
        return None

def start_sniffing(interface="eth0"):
    """
    Starts sniffing network traffic on the specified interface.
    """
    print(f"Starting packet capture on interface {interface}...")
    try:
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except PermissionError:
        print("Permission denied. Please run the script as root or with sudo.")
    except Exception as e:
        logging.error(f"Error during sniffing: {e}")
        print(f"Error during sniffing: {e}")

if __name__ == "__main__":
    # Change the interface name as per your setup
    start_sniffing(interface="eth0")
