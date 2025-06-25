import socket
import struct
import textwrap

# Constants
TCP = 6
UDP = 17

def main():
    # Create a raw socket to capture packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            print("\nEthernet Frame:")
            print(f"Destination MAC: {dest_mac}")
            print(f"Source MAC: {src_mac}")
            print(f"Protocol: {eth_proto}")
            
            # IPv4 packets (protocol 8)
            if eth_proto == 8:
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                
                print("\tIPv4 Packet:")
                print(f"\t\tVersion: {version}")
                print(f"\t\tHeader Length: {header_length}")
                print(f"\t\tTTL: {ttl}")
                print(f"\t\tProtocol: {proto}")
                print(f"\t\tSource: {src}")
                print(f"\t\tTarget: {target}")
                
                # TCP protocol
                if proto == TCP:
                    src_port, dest_port, sequence, ack, flags, data = tcp_segment(data)
                    print("\t\tTCP Segment:")
                    print(f"\t\t\tSource Port: {src_port}")
                    print(f"\t\t\tDestination Port: {dest_port}")
                    print(f"\t\t\tSequence: {sequence}")
                    print(f"\t\t\tAcknowledgment: {ack}")
                    print(f"\t\t\tFlags:")
                    print(f"\t\t\t\tURG: {flags['urg']}")
                    print(f"\t\t\t\tACK: {flags['ack']}")
                    print(f"\t\t\t\tPSH: {flags['psh']}")
                    print(f"\t\t\t\tRST: {flags['rst']}")
                    print(f"\t\t\t\tSYN: {flags['syn']}")
                    print(f"\t\t\t\tFIN: {flags['fin']}")
                    
                    if len(data) > 0:
                        # Simple check for HTTP data
                        if src_port == 80 or dest_port == 80:
                            print("\t\t\tHTTP Data:")
                            try:
                                print(textwrap.indent(str(data), '\t\t\t\t'))
                            except:
                                print("\t\t\t\tUnable to decode data")

                # UDP protocol
                elif proto == UDP:
                    src_port, dest_port, length, data = udp_segment(data)
                    print("\t\tUDP Segment:")
                    print(f"\t\t\tSource Port: {src_port}")
                    print(f"\t\t\tDestination Port: {dest_port}")
                    print(f"\t\t\tLength: {length}")
    
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    finally:
        conn.close()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'urg': (offset_reserved_flags & 32) >> 5,
        'ack': (offset_reserved_flags & 16) >> 4,
        'psh': (offset_reserved_flags & 8) >> 3,
        'rst': (offset_reserved_flags & 4) >> 2,
        'syn': (offset_reserved_flags & 2) >> 1,
        'fin': offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, ack, flags, data[offset:]

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

if __name__ == "__main__":
    main()
