# Honeypot with Scapy

This is a simple honeypot script that uses the `scapy` library to mimic a vulnerable service and gather information about attackers.

## Description

The honeypot script sets up a honeypot on a specified IP address and port. When an attacker attempts to connect to the target port, the script sends a SYN/ACK packet to the attacker, indicating that the port is open. The script then logs the attacker's IP address, port, and the time of the attempt.

## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)

## Usage

1. Make sure you have Python and the Scapy library installed.
2. Edit the `target_ip`, `target_port`, `honeypot_ip`, and `honeypot_port` variables in the script to match your setup.
3. Run the script using the command `python honeypot.py`.
4. The script will start sniffing packets on the target port and log the attacker's information when a SYN packet is received.

## Note

This script is for educational purposes only and should not be used for malicious activities. Always obtain proper authorization before running any honeypot or security testing tools.
