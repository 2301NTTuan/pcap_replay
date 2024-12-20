import socket
import struct

def create_gtpu_packet(teid, payload):

    version_flags = 0x30  
    message_type = 0xFF
    length = len(payload) 
    teid = teid

    gtpu_header = struct.pack("!BBHI", version_flags, message_type, length, teid)
    gtpu_packet = gtpu_header + payload
    return gtpu_packet

def run_client(server_ip, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    teid = 0x12345678
    payload = b"Hello, GTP-U!"
    gtpu_packet = create_gtpu_packet(teid, payload)

    client_socket.sendto(gtpu_packet, (server_ip, server_port))
    print(f"Sent GTP-U packet to {server_ip}:{server_port}")

    response, server_address = client_socket.recvfrom(4096)
    print(f"Received response from {server_address}: {response}")

    client_socket.close()

if __name__ == "__main__":
    run_client("192.168.10.6", 2152)
