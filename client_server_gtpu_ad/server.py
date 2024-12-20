import socket

# Server setup
UDP_IP = "192.168.10.6"  # Replace with your server's IP address
UDP_PORT = 2152         # GTP-U port

# Create the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((UDP_IP, UDP_PORT))

print(f"Server listening on {UDP_IP}:{UDP_PORT}")

while True:
    # Receive data from the client
    data, client_address = server_socket.recvfrom(65535)  # Maximum UDP packet size
    print(f"Received packet from {client_address}, length: {len(data)} bytes")

    # Echo the packet back to the client
    server_socket.sendto(data, client_address)
    print(f"Echoed packet back to {client_address}")
