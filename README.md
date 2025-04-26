# Network Packet Analyzer

A simple network packet analyzer tool similar to Wireshark, built with Python and Scapy.

## Features

- Real-time packet capture
- Basic packet analysis (IP, TCP, UDP, ICMP)
- Filtering capabilities
- Simple GUI interface

## Requirements

- Python 3.7 or higher
- Required packages (see requirements.txt)

## Installation

1. Clone this repository
2. Install the required packages:
```bash
pip install -r requirements.txt
```
OR 
just install the exe or .rar from the releases

## Usage

1. Run the application:
```bash
python network_analyzer.py
```
OR
Rune the exe file

2. Select your network interface from the dropdown menu
3. (Optional) Enter a filter expression (e.g., "tcp port 80")
4. Click "Start Capture" to begin capturing packets
5. Click "Stop Capture" to stop the capture

## Filter Examples

- `tcp port 80` - Capture HTTP traffic
- `udp port 53` - Capture DNS traffic
- `icmp` - Capture ICMP (ping) traffic
- `host 192.168.1.1` - Capture traffic to/from specific IP

## Notes

- You might need administrator/root privileges to capture packets
- The application shows basic packet information. For more detailed analysis, consider using Wireshark 
