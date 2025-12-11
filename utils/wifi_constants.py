
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

# Interfaccia di rete in Monitor Mode 
IFACE = "wlan0mon" 
BROADCAST = "ff:ff:ff:ff:ff:ff"