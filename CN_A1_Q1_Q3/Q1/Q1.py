import socket
import struct
import binascii


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

    while True:
        packet_data, _ = raw_socket.recvfrom(65535)
        src_mac, dest_mac, eth_type, packet_payload = parse_ethernet_header(packet_data)

        if eth_type == 0x0800:  # IPv4
            ip_version, ip_header_length, _, protocol, src_ip, dest_ip, tcp_packet = parse_ip_header(packet_payload)

            if protocol == 6:  # TCP
                tcp_header_info = parse_tcp_header(tcp_packet)

                if tcp_header_info:
                    src_port, dest_port, _, _, _, _, _ = tcp_header_info

                    print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dest_ip}, Destination Port: {dest_port}")

if __name__ == "__main__":
    main()
