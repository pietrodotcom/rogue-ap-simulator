# utils/wifi_constants.py
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

# Interfaccia di rete in Monitor Mode (da cambiare con la tua reale, es. wlan0mon)
IFACE = "wlan0mon" 
BROADCAST = "ff:ff:ff:ff:ff:ff"