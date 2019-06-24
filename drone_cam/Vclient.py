import logging
import socket
import threading, requests, time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# sending data client
clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSock.connect(('127.0.0.1', 7979))
print('The connection with the server has been verified.')
print(">> If the video data is not sniffing, check the Interface, IP and UDP ports and check the channel of the drone !!")
#clientSock.send('I am a client'.encode('utf-8'))

class sendData(threading.Thread):
    def __init__(self, packet):
        threading.Thread.__init__(self)
        self.packet = packet[2:]
        print (self.packet).encode('hex') #debug
    # sending data
    def run(self):
        clientSock.send(self.packet)
            
#2byte is seq
def showme(packet):
    drone_ip = "192.168.10.1"       #"192.168.35.89" #check 
    controller_ip = "192.168.10.4"  #"175.213.35.39" #check 
    # sniff filter
    if packet[IP].src == drone_ip and packet[IP].dst == controller_ip :
        if packet[UDP].dport == 6038 and packet[UDP].sport == 62514: #check dport=7797, sport=62512
            print (' >> Send Video Data !!')
            send = sendData(str(packet[UDP].payload))
            send.start()


def sniffing(interface, filter):
    sniff(iface=interface, filter=filter, prn=showme, count=0)


if __name__ == '__main__':
    interface = "ens33" # check 
    filter = "ip"
    sniffing(interface, filter)

