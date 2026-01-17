from abc import ABC, abstractmethod

# Interfaccia comune per tutti gli algoritmi (Strategy)
class DetectionStrategy(ABC):
    @abstractmethod
    def analyze(self, bssid, ssid, channel, timestamp, detected_aps, context):
        pass

# Strategia per il rilevamento di MAC fasulli (ConcreteStrategy)
class FakeMacStrategy(DetectionStrategy):
    def analyze(self, bssid, ssid, channel, timestamp, detected_aps, context):
        if bssid.startswith("00:00:00"):
            if bssid not in detected_aps:
                context._trigger_alert(f" Fake MAC rilevato: {bssid} (SSID: '{ssid}')", severity="HIGH")
            else:
                count = detected_aps[bssid].get('packet_count', 0)
                if count % 5 == 0 and count > 0:
                    context._trigger_alert(f" Fake MAC persistente: {bssid} ({count} beacon)", severity="MEDIUM")

# Strategia per l'intervallo dei beacon (ConcreteStrategy)
class BeaconIntervalStrategy(DetectionStrategy):
    def analyze(self, bssid, ssid, channel, timestamp, detected_aps, context):
        if bssid in detected_aps:
            last_seen = detected_aps[bssid]['last_seen']
            delta = timestamp - last_seen
            if delta < 0.3:
                context._trigger_alert(f"Beacon Interval anomalo: {ssid} ({bssid}) - {delta*1000:.1f}ms", severity="MEDIUM")

# Strategia per il cambio canale (ConcreteStrategy)
class ChannelHoppingStrategy(DetectionStrategy):
    def analyze(self, bssid, ssid, channel, timestamp, detected_aps, context):
        if bssid in detected_aps:
            last_channel = detected_aps[bssid].get('channel', 0)
            if channel > 0 and last_channel > 0 and last_channel != channel:
                context._trigger_alert(f" Channel Hopping rilevato: {ssid} ({bssid}) - Ch {last_channel} → {channel}", severity="LOW")
