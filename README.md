# SentinelAI-IPS
SentinelAI-IPS is an Intrusion Prevention System designed to detect and prevent unauthorized access or malicious activities in a network. It leverages machine learning models trained on network traffic data to analyze packets in real-time and mitigate threats by blocking malicious IPs or traffic.


## Features

- **Real-time Traffic Analysis**: Monitors network traffic continuously for potential threats.

- **Anomaly Detection**: Uses machine learning to identify unusual patterns in traffic.

- **Attack Classification**: Classifies detected threats into specific attack types.

- **Automated Threat Prevention**: Blocks malicious IPs or suspicious traffic upon detection.

- **Logging**: Maintains detailed logs for detected intrusions.


## Getting Started

1. Prerequisites

- Python 3.8 or later

- pip (Python package installer)

2. Installation

- Clone the repository:
```
git clone https://github.com/Nikosane/SentinelAI-IPS.git
cd SentinelAI-IPS
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

4. Set up the dataset:

- Place raw network traffic data in `data/raw_network_data.csv`.

- Use the `src/feature_extractor.py` script to preprocess the data and save it as `data/processed_data.csv`.
