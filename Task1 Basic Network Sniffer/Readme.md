
# TASK 1 : Basic Network Sniffer

## Description

Build a network sniffer in Python that captures and
analyzes network traffic. This project will help you
understand how data flows on a network and how
network packets are structured.


---

# Network Packet Analyzer and Attack Detection - `Sniffing.py`

This Python project captures and analyzes network packets in real time to detect DoS attacks and SSH brute force attempts. It uses the `scapy` library for packet capture and `rich` for interactive console display.


## Features

- Real-time packet capture on a specified network interface.
- Packet analysis to detect external and internal IP addresses.
- Detection of DoS attacks and SSH brute force attempts.
- Display results in an interactive table using the `rich` library.
- Export analysis results to CSV file (`ip_analyse_resultat.csv`).
- Save network capture in `.pcap` format.
## Required
- Python 3.x

## Installation
1. Clone this repository and access the project folder:
   ```bash
   git clone https://https://github.com/571LL01/votre-repo.git
   cd votre-repo
   ```

2. Install the necessary dependencies using the `requirements.txt` file:
   ```bash
   pip install -r requirements.txt
   ```

## Use
1. List the network interfaces available on your machine by running the script :
   ```bash
   python3 Sniffing.py
   ```
   This will display the available interfaces.

2. Specify the interface to be used for sniffing:
   ```bash
   Specify the network interface to be sniffed (e.g. wlan0):
   ```
   The analyzer will start capturing packets on the specified interface.
3. Captured packets will be analyzed and the results displayed in an interactive table. Information includes:
   - Source IP.
   - Network type (Internal/External).
   - Protocol used (TCP/UDP).
   - Source port.
   - Additional information on external IPs (location, organization, etc.).

4. A `.pcap` file containing the network capture will be generated, together with a CSV file of the analysis results (`ip_analyse_resultat.csv`).

## Order example
```bash
python3 Sniffing.py
```

## Attack alert
The script detects the following situations and generates alerts in the console:
- **DoS Attack**: More than 100 requests from a single IP in less than 60 seconds.
- SSH Force Attack**: More than 10 SSH connection attempts from a single IP in less than 60 seconds.


## Warnings
- This script is intended for educational use and detection in controlled environments. Use on a production network requires adjustments and legal authorization.
- The collection of information on external IPs must comply with local privacy laws and regulations.

## Contribute
Contributions are welcome! To propose a new feature or report a problem, open a *issue* or submit a *pull request*.
