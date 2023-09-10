import socket
import struct
import binascii
import hashlib

def calculate_tcp_checksum(tcp_packet):
    # Split the TCP packet into 16-bit words
    words = [tcp_packet[i:i+2] for i in range(0, len(tcp_packet), 2)]

    # Initialize the checksum to 0
    checksum = 0

    # Sum all the 16-bit words
    for word in words:
        checksum += int.from_bytes(word, byteorder='big')

    # Handle any carry out of the most significant bit
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Take the one's complement
    checksum = ~checksum & 0xFFFF

    return checksum

def parse_ethernet_header(packet):
    eth_header = struct.unpack('!6s6sH', packet[:14])
    src_mac = binascii.hexlify(eth_header[0]).decode('utf-8')
    dest_mac = binascii.hexlify(eth_header[1]).decode('utf-8')
    eth_type = eth_header[2]
    return src_mac, dest_mac, eth_type, packet[14:]

def parse_ip_header(packet):
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    ip_version_and_length = ip_header[0]
    ip_version = ip_version_and_length >> 4
    ip_header_length = (ip_version_and_length & 0x0F) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return ip_version, ip_header_length, ttl, protocol, src_ip, dest_ip, packet[ip_header_length:]

def parse_tcp_header(packet):
    if len(packet) >= 20:  # Check if there are at least 20 bytes for the TCP header
        tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence_number = tcp_header[2]
        ack_number = tcp_header[3]
        data_offset_and_flags = tcp_header[4]
        tcp_header_length = (data_offset_and_flags >> 4) * 4
        flags = tcp_header[5]
        return src_port, dest_port, sequence_number, ack_number, tcp_header_length, flags, packet[tcp_header_length:]
    else:
        return None

def main():
    # Create a raw socket to capture packets
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sum = 0

    while True:
        packet_data, _ = raw_socket.recvfrom(65535)
        src_mac, dest_mac, eth_type, packet_payload = parse_ethernet_header(packet_data)

        if eth_type == 0x0800:  # IPv4
            ip_version, ip_header_length, _, protocol, src_ip, dest_ip, tcp_packet = parse_ip_header(packet_payload)

            if protocol == 6:  # TCP
                tcp_header_info = parse_tcp_header(tcp_packet)

                if tcp_header_info:
                    src_port, dest_port, _, _, tcp_header_length, _, payload = tcp_header_info

                    # Convert payload to ASCII
                    try:
                        ascii_payload = payload.decode('utf-8')
                    except UnicodeDecodeError:
                        ascii_payload =  binascii.hexlify(payload).decode('utf-8')
                    
                    # I come from localhost --- Q5
                    if(src_ip == "127.0.0.1"):
                        print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dest_ip}, Destination Port: {dest_port}")
                        print(f"ASCII Payload: {ascii_payload}")


if __name__ == "__main__":
    main()
