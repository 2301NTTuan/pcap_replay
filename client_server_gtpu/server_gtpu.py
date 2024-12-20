import socket

def run_server(server_ip, server_port):

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        data, client_address = server_socket.recvfrom(4096)
        print(f"Received {len(data)} bytes from {client_address}")

        # Send the received packet back to the client
        server_socket.sendto(data, client_address)
        print(f"Sent packet back to {client_address}")

# Example: Run the server on localhost, port 2152
if __name__ == "__main__":
    run_server("192.168.10.6", 2152)
