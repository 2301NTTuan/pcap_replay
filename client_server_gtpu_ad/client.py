import socket
import struct

# ----------------------
# Build the GTP-U packet (reuse the previous logic for packet construction)
# ----------------------
def create_gtpu_packet():
    # Ethernet Header
    dst_mac = b'\x00\x11\x22\x33\x44\x55'  # Destination MAC
    src_mac = b'\x66\x77\x88\x99\xaa\xbb'  # Source MAC
    eth_type = b'\x08\x00'  # IPv4

    ethernet_header = dst_mac + src_mac + eth_type

    # Outer IP Header
    version_ihl = 0x45
    dscp_ecn = 0
    total_length = 0  # Will calculate later
    identification = 54321
    flags_fragment_offset = 0
    ttl = 64
    protocol = 17  # UDP
    checksum = 0
    src_ip = socket.inet_aton('192.168.1.1')
    dst_ip = socket.inet_aton('192.168.10.6')

    outer_ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip
    )

    # Outer UDP Header
    src_port = 2152
    dst_port = 2152
    udp_length = 0
    udp_checksum = 0

    outer_udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    # GTP-U Header
    version_flags = 0x30
    message_type = 0xFF
    payload_length = 0
    teid = 0x12345678

    gtpu_header = struct.pack("!BBHI", version_flags, message_type, payload_length, teid)

    # Inner IP Header
    inner_version_ihl = 0x45
    inner_dscp_ecn = 0
    inner_total_length = 0
    inner_identification = 12345
    inner_flags_fragment_offset = 0
    inner_ttl = 64
    inner_protocol = 17
    inner_checksum = 0
    inner_src_ip = socket.inet_aton('10.0.0.1')
    inner_dst_ip = socket.inet_aton('10.0.0.2')

    inner_ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        inner_version_ihl,
        inner_dscp_ecn,
        inner_total_length,
        inner_identification,
        inner_flags_fragment_offset,
        inner_ttl,
        inner_protocol,
        inner_checksum,
        inner_src_ip,
        inner_dst_ip
    )

    # Inner UDP Header
    inner_src_port = 1234
    inner_dst_port = 5678
    inner_udp_length = 0
    inner_udp_checksum = 0

    inner_udp_header = struct.pack("!HHHH", inner_src_port, inner_dst_port, inner_udp_length, inner_udp_checksum)

    # Payload
    payload = b"Hello"

    # Calculate Lengths
    inner_udp_length = len(inner_udp_header) + len(payload)
    inner_total_length = len(inner_ip_header) + inner_udp_length

    outer_udp_length = len(outer_udp_header) + len(gtpu_header) + inner_total_length
    outer_total_length = len(outer_ip_header) + outer_udp_length

    payload_length = len(gtpu_header) + inner_total_length

    # Update headers with correct lengths
    inner_ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        inner_version_ihl,
        inner_dscp_ecn,
        inner_total_length,
        inner_identification,
        inner_flags_fragment_offset,
        inner_ttl,
        inner_protocol,
        inner_checksum,
        inner_src_ip,
        inner_dst_ip
    )

    inner_udp_header = struct.pack("!HHHH", inner_src_port, inner_dst_port, inner_udp_length, inner_udp_checksum)

    outer_ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        outer_total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip
    )

    outer_udp_header = struct.pack("!HHHH", src_port, dst_port, outer_udp_length, udp_checksum)
    gtpu_header = struct.pack("!BBHI", version_flags, message_type, payload_length, teid)

    # Assemble Packet
    return (
        ethernet_header +
        outer_ip_header +
        outer_udp_header +
        gtpu_header +
        inner_ip_header +
        inner_udp_header +
        payload
    )


# ----------------------
# Client setup
# ----------------------
UDP_IP = "192.168.10.6"  # Server IP
UDP_PORT = 2152         # Server port

# Create the socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Create GTP-U packet
packet = create_gtpu_packet()

# Send packet to server
client_socket.sendto(packet, (UDP_IP, UDP_PORT))
print(f"Packet sent to {UDP_IP}:{UDP_PORT}")

# Receive echoed packet
response, server_address = client_socket.recvfrom(65535)
print(f"Received packet from {server_address}, length: {response} ")

client_socket.close()
