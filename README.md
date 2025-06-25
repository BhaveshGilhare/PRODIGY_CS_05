# PRODIGY_CS_05
Network Packet Analyzer
This Python-based packet sniffer captures and analyzes network packets using standard socket and struct modules. It extracts and displays important details such as:
*Ethernet Frame: Displays source and destination MAC addresses, and protocol type.
*IPv4 Packet: Shows version, header length, TTL, source and target IP addresses.
*TCP Segment: Includes source and destination ports, sequence and acknowledgment numbers, and flags.
*HTTP Data: Displays HTTP request details if applicable.

Features: Capture live network traffic on a specified network interface. Display key information: Source and destination IP addresses Protocol used (e.g., TCP, UDP)

Requirements: Python 3.x and no additional libraries needed (uses standard socket and struct modules)
