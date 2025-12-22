
from scapy.all import Dot11, Dot11Elt
import time
import datetime
import threading
from models.strategies import (FakeMacStrategy, BeaconIntervalStrategy, ChannelHoppingStrategy)

class DetectorModel:
    def __init__(self):
        self.detected_aps = {}
        self.alerts = []
        self.is_scanning = False
        self.alert_counter = 0
        self.lock = threading.Lock()
        self._strategies = [
            FakeMacStrategy(),
            BeaconIntervalStrategy(),
            ChannelHoppingStrategy()
        ]

    def analyze_packet(self, pkt):
        """Analizza un pacchetto beacon e applica euristiche"""
        if not pkt.haslayer(Dot11):
            return
        
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
            bssid = pkt.addr2
            
            # Estrae SSID
            try:
                ssid = pkt.info.decode('utf-8', errors='ignore') if hasattr(pkt, 'info') else "Unknown"
            except:
                ssid = "Unknown"
            
            # Estrae canale 
            channel = self._extract_channel(pkt)

            timestamp = time.time()
            
            with self.lock:
                self._check_heuristics(bssid, ssid, channel, timestamp)

    def _extract_channel(self, pkt):
        """Estrae il canale dal pacchetto beacon"""
        try:
            # Itera su tutti gli elementi Dot11Elt
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                # ID=3 è il DSset (channel info)
                if elt.ID == 3 and len(elt.info) > 0:
                    # Supporta sia byte che int
                    if isinstance(elt.info, bytes):
                        return elt.info[0] if elt.info[0] < 256 else ord(elt.info[0:1])
                    else:
                        return int(elt.info)
                elt = elt.payload.getlayer(Dot11Elt)
            return 0
        except Exception as e:
            return 0

    def _check_heuristics(self, bssid, ssid, channel, timestamp):
        """Applica le euristiche delegando alle strategie (Strategy Pattern) [cite: 911]"""
        
        # Esegue ogni strategia registrata
        for strategy in self._strategies:
            strategy.analyze(bssid, ssid, channel, timestamp, self.detected_aps, self)
        
        # Aggiorna il tracking (stato interno del Context necessario per le strategie future)
        self._update_tracking(bssid, ssid, channel, timestamp)

    def _update_tracking(self, bssid, ssid, channel, timestamp):
        """Mantiene aggiornato lo stato degli AP tracciati"""
        if bssid not in self.detected_aps:
            self.detected_aps[bssid] = {
                'ssid': ssid, 'first_seen': timestamp, 'last_seen': timestamp,
                'channel': channel, 'packet_count': 1
            }
        else:
            self.detected_aps[bssid].update({
                'last_seen': timestamp, 'channel': channel,
                'packet_count': self.detected_aps[bssid]['packet_count'] + 1
            })    

    def _trigger_alert(self, message, severity="INFO"):
        """Genera un alert con timestamp"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.alert_counter += 1
        
        prefix = {
            "HIGH": "!!!",
            "MEDIUM": "!!",
            "LOW": "!",
            "INFO": "info"
        }.get(severity, "•")
        
        full_message = f"[{timestamp}] {prefix} #{self.alert_counter}: {message}"
        self.alerts.append(full_message)
        print(f"[DETECTOR] {full_message}")
        
        if len(self.alerts) > 25:
            self.alerts.pop(0)

    def clear_alerts(self):
        """Svuota solo gli alert, ma non il tracking"""
        with self.lock:
            old_count = len(self.alerts)
            self.alerts = []
            print(f"[DETECTOR] Cancellati {old_count} alert. Tracking: {len(self.detected_aps)} AP")
