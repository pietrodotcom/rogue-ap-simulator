# models/detector_model.py
from scapy.all import sniff, Dot11, Dot11Elt
import time

class DetectorModel:
    def __init__(self):
        self.detected_aps = {} # Dizionario per tracciare gli AP visti
        self.alerts = []
        self.is_scanning = False

    def analyze_packet(self, pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8: # Beacon frame
            bssid = pkt.addr2
            ssid = pkt.info.decode('utf-8', errors='ignore')
            try:
                # Estrazione canale (spesso nel payload o radiotap header, semplificato qui)
                channel = int(ord(pkt[Dot11Elt:3].info)) 
            except:
                channel = 0
            
            timestamp = time.time()
            
            # Logica di Rilevamento
            self._check_heuristics(bssid, ssid, channel, timestamp)

    def _check_heuristics(self, bssid, ssid, channel, timestamp):
        # 1. Check Differenze Beacon (Intervallo)
        if bssid in self.detected_aps:
            last_seen = self.detected_aps[bssid]['last_seen']
            delta = timestamp - last_seen
            
            # Se i beacon arrivano troppo velocemente (Beacon Flooding)
            if delta < 0.05: 
                self._trigger_alert(f"Anomalia Beacon Interval rapido da {ssid} ({bssid})")

            # 2. Channel Hopping Sospetto
            last_channel = self.detected_aps[bssid]['channel']
            if last_channel != channel:
                self._trigger_alert(f"Channel Hopping rilevato su {ssid}: Ch {last_channel} -> {channel}")

        # 3. Mismatch Vendor/Potenza (Simulazione)
        # Esempio: Se il MAC è 00:11:22... (Cisco) ma il segnale è debole o strano
        # Qui simuliamo un controllo OUI banale
        if bssid.startswith("00:00:00"): 
             self._trigger_alert(f"Vendor Mismatch/Fake MAC rilevato: {bssid}")

        # Aggiorna lo stato
        self.detected_aps[bssid] = {
            'ssid': ssid,
            'last_seen': timestamp,
            'channel': channel
        }

    def _trigger_alert(self, message):
        # Evita duplicati spam
        if message not in self.alerts:
            self.alerts.append(message)
            return True # Segnala al controller che c'è un nuovo alert
        return False

    def start_sniffing(self, callback_func):
        self.is_scanning = True
        # Sniffing bloccante, quindi andrà in un thread nel controller
        # prn=callback_func chiama la funzione per ogni pacchetto
        # sniff(iface=IFACE, prn=lambda x: self.analyze_packet(x), store=0)
        print("[MODEL] Detector avviato (Simulation Mode)")
    
    def clear_alerts(self):
        self.alerts = []  # Svuota la lista in memoria