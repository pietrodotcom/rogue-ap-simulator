# models/simulator_model.py
import time
import threading
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from utils.wifi_constants import BROADCAST
import queue

class RogueAPModel:
    def __init__(self):
        self.is_running = False
        self.ssid = "FreeWiFi"
        self.bssid = "00:11:22:33:44:55"
        self.channel = 6
        self.interval = 0.1
        self.packet_queue = None
        self.attack_thread = None

    def configure(self, ssid, bssid, power_level, interval, channel=6):
        self.ssid = ssid if ssid else "FreeWiFi"
        self.bssid = bssid if bssid else "00:00:00:11:22:33"
        self.interval = float(interval) if interval else 0.1
        self.channel = int(channel) if channel else 6
        print(f"[SIMULATOR] Configurato: SSID={self.ssid}, BSSID={self.bssid}, Channel={self.channel}, Interval={self.interval}s")

    def _build_packet(self):
        dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=self.bssid, addr3=self.bssid)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=self.ssid.encode(), len=len(self.ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(self.channel).encode()) 
        packet = RadioTap() / dot11 / beacon / essid / dsset
        return packet

    def start_attack(self, packet_queue):
        if self.is_running:
            print("[SIMULATOR] Attacco già in corso!")
            return
        
        self.is_running = True
        self.packet_queue = packet_queue
        print(f"[SIMULATOR] Avvio Rogue AP: {self.ssid} ({self.bssid}) su canale {self.channel}")
        
        self.attack_thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self.attack_thread.start()

    def _beacon_loop(self):
        beacon_count = 0
        while self.is_running:
            try:
                packet = self._build_packet()
                
                # Aggiunge alla queue solo se non è piena
                try:
                    self.packet_queue.put(packet, block=False)
                    beacon_count += 1
                    if beacon_count % 10 == 0:
                        print(f"[SIMULATOR] Inviati {beacon_count} beacon per {self.ssid} (Ch {self.channel})")
                except queue.Full:
                    print("[SIMULATOR] Queue piena, attendo...")
                    time.sleep(0.5)
                
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"[SIMULATOR] Errore: {e}")
                self.is_running = False
        
        print(f"[SIMULATOR] Fermato dopo {beacon_count} beacon")

    def stop_attack(self):
        if not self.is_running:
            print("[SIMULATOR] Nessun attacco attivo")
            return
        
        self.is_running = False
        print(f"[SIMULATOR] Fermando Rogue AP: {self.ssid}")
        
        # Attendi che il thread termini
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=2)
