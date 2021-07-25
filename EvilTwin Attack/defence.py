import os
import sys
import time
from scapy.layers.dot11 import Dot11Beacon
from scapy.sendrecv import sniff
from threading import Thread


timeOut = 10000
ap_list = {}
evil_ap_list = {}


def scanEvilAP(pkt):
    if pkt.haslayer(Dot11Beacon):  
        if pkt.type == 0 and pkt.subtype == 8: 
            if not (pkt.info.decode("utf-8") in ap_list):  
                ap_list[pkt.info.decode("utf-8")] = pkt.addr3
            elif (ap_list[pkt.info.decode(
                    "utf-8")] != pkt.addr3):
                if not (pkt.info.decode("utf-8") in evil_ap_list):
                    print("%s" % (pkt.info.decode("utf-8")))
                    evil_ap_list[pkt.info.decode("utf-8")] = pkt.info.decode("utf-8")
        


def start_monitor(interfaceName):
    print(f'Change {interfaceName} to monitor mode')
    os.system(f'sudo ifconfig {interfaceName} down')
    os.system(f'sudo iwconfig {interfaceName} mode monitor')
    os.system(f'sudo ifconfig {interfaceName} up')

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interfaceName} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(0.5)



def switch_channels():
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()





if __name__ == '__main__':
    interfaceName = sys.argv[1]
    start_monitor(interfaceName)
    switch_channels()
    print("Scanning.......\n")
    print("duplicated networks founds, be carefull connecting to them:")
    sniff(prn=scanEvilAP, iface=interfaceName, count=timeOut)  # iface - interface to sniff , prn - function
