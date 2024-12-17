import pandas as pd

def extract_features(packet):
    try:
        features = {
            "src_ip": packet.get("src_ip", ""),
            "dst_ip": packet.get("dst_ip", ""),
            "protocol": packet.get("protocol", ""),
            "size": packet.get("size", 0),
        }
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def preprocess_data(raw_data_path, output_path):
    try:
        raw_data = pd.read_csv(raw_data_path)

        raw_data["protocol"] = raw_data["protocol"].astype(int)

        raw_data.to_csv(output_path, index=False)
        print(f"Processed data saved to {output_path}")
    except Exception as e:
        print(f"Error preprocessing data: {e}")

if __name__ == "__main__":
    
    raw_data_path = "../data/raw_network_data.csv"
    output_path = "../data/processed_data.csv"
    preprocess_data(raw_data_path, output_path)
