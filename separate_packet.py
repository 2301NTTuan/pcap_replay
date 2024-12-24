import struct

# PCAP file paths
input_pcap = "input.pcap"
uplink_pcap = "uplink.pcap"
downlink_pcap = "downlink.pcap"

# Define client and server IPs
client_ip = b'\xc0\xa8\x01\x64'  # 192.168.1.100
server_ip = b'\xc0\xa8\x01\xc8'  # 192.168.1.200

def get_ethertype(packet_data):
    """Extract EtherType, handling VLAN-tagged frames."""
    if len(packet_data) >= 14:
        eth_type = struct.unpack(">H", packet_data[12:14])[0]
        if eth_type == 0x8100 and len(packet_data) >= 18:  # Check VLAN tag
            eth_type = struct.unpack(">H", packet_data[16:18])[0]
        return eth_type
    return None

# Open input PCAP file
with open(input_pcap, "rb") as f:
    # Read the PCAP global header (24 bytes)
    global_header = f.read(24)

    # Buffers for uplink and downlink packets
    uplink_packets = []
    downlink_packets = []

    while True:
        # Read the packet header (16 bytes)
        packet_header = f.read(16)
        if not packet_header:
            break  # End of file

        # Parse packet header
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", packet_header)

        # Read the packet data
        packet_data = f.read(incl_len)

        # Extract EtherType, considering VLAN-tagged frames
        eth_type = get_ethertype(packet_data)

        # Check if it's an IPv4 packet (EtherType = 0x0800)
        if eth_type == 0x0800:  # IPv4
            # Extract IP header (starts at offset 14 for non-VLAN, 18 for VLAN)
            ip_header_offset = 14 if struct.unpack(">H", packet_data[12:14])[0] != 0x8100 else 18
            ip_header = packet_data[ip_header_offset:ip_header_offset + 20]

            # Extract source and destination IP addresses
            src_ip = ip_header[12:16]
            dst_ip = ip_header[16:20]

            # Classify as uplink or downlink
            if src_ip == client_ip and dst_ip == server_ip:
                uplink_packets.append((packet_header, packet_data))
            elif src_ip == server_ip and dst_ip == client_ip:
                downlink_packets.append((packet_header, packet_data))

# Write the new PCAP files
def write_pcap(output_file, packets):
    with open(output_file, "wb") as f:
        # Write global header
        f.write(global_header)

        # Write packets
        for packet_header, packet_data in packets:
            f.write(packet_header)
            f.write(packet_data)

# Save uplink and downlink packets
write_pcap(uplink_pcap, uplink_packets)
write_pcap(downlink_pcap, downlink_packets)

print("Uplink packets saved to", uplink_pcap)
print("Downlink packets saved to", downlink_pcap)
