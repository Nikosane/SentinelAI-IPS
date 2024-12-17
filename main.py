from src.traffic_sniffer import start_sniffer
from src.intrusion_preventer import start_intrusion_prevention

def main():
    print("Welcome to SentinelAI-IPS!")
    print("Initializing the Intrusion Prevention System...")

    try:
        interface = "eth0"  
        print(f"Starting network traffic monitoring on interface: {interface}")

        start_intrusion_prevention(interface=interface)
    except KeyboardInterrupt:
        print("\nSystem shutdown initiated by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("SentinelAI-IPS has been stopped.")

if __name__ == "__main__":
    main()
