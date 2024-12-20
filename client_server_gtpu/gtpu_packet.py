import struct
import socket

def create_gtpu_packet(teid, payload):
    # GTP-U Header Fields
    version_flags = 0x30  # Version = 1 (3 bits), Protocol Type = 1 (1 bit), Reserved = 0 (4 bits)
    message_type = 0xFF   # T-PDU (payload)
    length = len(payload)  # Length of the payload
    teid = teid            # Tunnel Endpoint Identifier (32-bit)

    # Pack GTP-U Header
    gtpu_header = struct.pack("!BBHI", version_flags, message_type, length, teid)

    # Combine header and payload
    gtpu_packet = gtpu_header + payload
    return gtpu_packet

def create_udp_packet(src_ip, dst_ip, src_port, dst_port, gtpu_packet):
    # UDP Header Fields
    udp_length = 8 + len(gtpu_packet)  # UDP header (8 bytes) + payload
    checksum = 0                       # Placeholder for checksum (optional)

    # Pack UDP Header
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, checksum)

    # Combine header and payload
    udp_packet = udp_header + gtpu_packet
    return udp_packet

def create_ip_packet(src_ip, dst_ip, udp_packet):

    # IP Header Fields
    version_ihl = 0x45  # IPv4 and Header Length = 20 bytes
    tos = 0x00          # Type of Service
    total_length = 20 + len(udp_packet)  # IP header (20 bytes) + payload
    identification = 54321
    flags_offset = 0x4000  # Don't Fragment flag
    ttl = 64               # Time to Live
    protocol = 17          # UDP
    checksum = 0           # Placeholder for checksum
    src_ip_bytes = socket.inet_aton(src_ip)  # Convert IP string to bytes
    dst_ip_bytes = socket.inet_aton(dst_ip)

    # Pack IP Header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_length, identification,
        flags_offset, ttl, protocol, checksum, src_ip_bytes, dst_ip_bytes
    )

    # Combine header and payload
    ip_packet = ip_header + udp_packet
    return ip_packet

# Example Usage
if __name__ == "__main__":
    src_ip = "192.168.1.1"
    dst_ip = "192.168.2.1"
    src_port = 2152
    dst_port = 2152
    teid = 0x12345678
    payload = b"Hello, GTP-U!"  # Example payload

    # Create GTP-U packet
    gtpu_packet = create_gtpu_packet(teid, payload)

    # Create UDP packet
    udp_packet = create_udp_packet(src_ip, dst_ip, src_port, dst_port, gtpu_packet)

    # Create IP packet
    ip_packet = create_ip_packet(src_ip, dst_ip, udp_packet)

    # Save to a file for analysis
    with open("gtpu_packet.bin", "wb") as f:
        f.write(ip_packet)

    print("GTP-U packet created and saved to 'gtpu_packet.bin'.")
