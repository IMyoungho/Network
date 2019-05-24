import socket
import sys
from threading import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_addr = ('localhost',7979)
print >> sys.stderr, "starting up on %s port %s" % server_addr
sock.bind(server_addr)
sock.listen(1)
print >> sys.stderr, 'Wating for a connection'
connectionsock, client_addr = sock.accept()

print(str(client_addr),'is Connected.')
connectionsock.send(' Hi! my name is Ho\'s  Drone Video Server.'.encode('utf-8'))

while True:
	data = connectionsock.recv(4096)
	print data.encode('hex')
	# add video stream programming