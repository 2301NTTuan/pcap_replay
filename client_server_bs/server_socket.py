import socket

IPandPortServer = ("192.168.10.6", 8080)
bufferSize = 1024

msgFromServer =  "Hello UDP Client"
bytesToSend = str.encode(msgFromServer)

UDPServerSocket = socket.socket(family = socket.AF_INET, type = socket.SOCK_DGRAM)

UDPServerSocket.bind(IPandPortServer)

print("UDP Server up and listening.....")

while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    clientMsg = "Message from Client: {}".format(message)
    clientIP = "Client IP Address: {}".format(address)

    print(clientMsg)
    print(clientIP)

    UDPServerSocket.sendto(bytesToSend, address)