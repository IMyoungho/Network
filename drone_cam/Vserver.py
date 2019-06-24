import socket
import sys
from threading import *
import cv2
#python3 name > aaa.mp4

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)#temp

server_addr = ('localhost',7979)
sock.bind(server_addr)
sock.listen(1)
connectionsock, client_addr = sock.accept()

print(str(client_addr),'is Connected.')
connectionsock.send(' Hi! my name is Ho\'s  Drone Video Server.'.encode('utf-8'))


while True:
	data = connectionsock.recv(4096)
	sys.stdout.buffer.write(data)
