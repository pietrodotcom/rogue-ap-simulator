# models/simulator_model.py
import time
import threading
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
from utils.wifi_constants import IFACE, BROADCAST

class RogueAPModel:
    def __init__(self):
        self.is_running = False
        self.ssid = "FreeWiFi"
        self.bssid = "00:11:22:33:44:55" # Fake MAC
        self.channel = 6
        self.interval = 0.1 # 100ms standard

    def configure(self, ssid, bssid, power_level, interval):
        self.ssid = ssid
        self.bssid = bssid
        # Power level simulator logic (simplified injection)
        self.interval = float(interval)

    def _build_packet(self):
        # Costruzione layer 802.11
        dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=self.bssid, addr3=self.bssid)
        # Beacon frame
        beacon = Dot11Beacon(cap='ESS+privacy')
        # Information Elements (SSID, Channel, Rates)
        essid = Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(self.channel))
        
        # Scapy packet composition
        packet = RadioTap() / dot11 / beacon / essid / dsset
        return packet

    def start_attack(self):
        self.is_running = True
        packet = self._build_packet()
        print(f"[MODEL] Starting Rogue AP: {self.ssid} on {self.bssid}")
        
        # Thread separato per non bloccare la UI
        t = threading.Thread(target=self._beacon_loop, args=(packet,))
        t.daemon = True
        t.start()

    def _beacon_loop(self, packet):
        while self.is_running:
            try:
                # In un caso reale usiamo sendp su IFACE
                # sendp(packet, iface=IFACE, verbose=0)
                print(f"[TRAFFIC] Sent Beacon for {self.ssid}") 
                time.sleep(self.interval)
            except Exception as e:
                print(f"Error sending packet: {e}")
                self.is_running = False

    def stop_attack(self):
        self.is_running = False