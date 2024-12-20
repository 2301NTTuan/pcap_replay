import socket
import time

msgFromClient = "Hello UDP Server"
bytesToSend = str.encode(msgFromClient)
serverAddressPort = ("192.168.10.6", 8080)
bufferSize = 1024

UDPClientSocket = socket.socket(family = socket.AF_INET, type = socket.SOCK_DGRAM)

while(True):
    UDPClientSocket.sendto(bytesToSend, serverAddressPort)

    msgFromServer = UDPClientSocket.recvfrom(bufferSize)

    msg = "Message from Server {}".format(msgFromServer[0])

    print(msg)
    time.sleep(1)

