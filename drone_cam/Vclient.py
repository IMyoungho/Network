import logging
import socket
import threading, requests, time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# sending data client
clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSock.connect(('127.0.0.1', 7979))
print('The connection with the server has been verified.')
#clientSock.send('I am a client'.encode('utf-8'))



class sendData(threading.Thread):
    def __init__(self, packet):
        threading.Thread.__init__(self)
        self.packet = packet

    # sending data
    def run(self):
            clientSock.send(self.packet)
            

def showme(packet):
    drone_ip = "192.168.10.1"       #"192.168.35.89" #check 
    controller_ip = "192.168.10.2"  #"175.213.35.39" #check 
    # sniff filter

    if packet[IP].src == drone_ip and packet[IP].dst == controller_ip :
        if packet[UDP].dport == 7797 and packet[UDP].sport == 62512: #check 
            #only data packet
            #print(packet[UDP].payload)
            print (' >> Send Video Data !!')
            send = sendData(str(packet[UDP].payload))
            send.start()


def sniffing(interface, filter):
    sniff(iface=interface, filter=filter, prn=showme, count=0)


if __name__ == '__main__':
    interface = "wlan0" # check 
    filter = "ip"
    sniffing(interface, filter)

