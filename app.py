from flask import Flask, render_template, request, jsonify
from models.simulator_model import RogueAPModel
from models.detector_model import DetectorModel
import threading
import time
import queue

app = Flask(__name__)

rogue_ap = RogueAPModel()
detector = DetectorModel()
packet_queue = queue.Queue(maxsize=100)

# --- SIMULAZIONE INTEGRATA ---
def detector_loop():
    print("[SYSTEM] Thread Detector avviato...")
    while True:
        if detector.is_scanning:
            # Processa tutti i pacchetti disponibili nella queue
            packets_processed = 0
            while not packet_queue.empty() and packets_processed < 10:
                try:
                    pkt = packet_queue.get(timeout=0.1)
                    detector.analyze_packet(pkt)
                    packets_processed += 1
                except queue.Empty:
                    break
            
            if packets_processed > 0:
                print(f"[DETECTOR] Processati {packets_processed} pacchetti")
            
            time.sleep(0.2)  # Pausa
        else:
            time.sleep(0.5)

t = threading.Thread(target=detector_loop)
t.daemon = True
t.start()

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/start_sim', methods=['POST'])
def start_sim():
    # Previene multiple injection
    if rogue_ap.is_running:
        return jsonify({"status": "Già in esecuzione", "error": True})
    
    data = request.json
    rogue_ap.configure(
        data.get('ssid', 'FreeWiFi'), 
        data.get('bssid', '00:00:00:11:22:33'), 
        #"High", 
        data.get('interval', 0.1),
        data.get('channel', 6) 
    )
    
    # Svuotamento della queue 
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            break
    
    rogue_ap.start_attack(packet_queue)
    return jsonify({"status": "Attacco Avviato", "error": False})

@app.route('/api/stop_sim', methods=['POST'])
def stop_sim():
    rogue_ap.stop_attack()
    return jsonify({"status": "Attacco Fermato"})

@app.route('/api/toggle_detector', methods=['POST'])
def toggle_detector():
    status = request.json.get('status')
    print(f"[DEBUG] Switch detector: {status}")
    
    was_scanning = detector.is_scanning
    detector.is_scanning = (status == 'on')
    
    if detector.is_scanning and not was_scanning:
        print("[DETECTOR] Rilevazione ATTIVATA")
    elif not detector.is_scanning:
        print("[DETECTOR] Rilevazione DISATTIVATA")
    
    return jsonify({"status": "Ok", "is_scanning": detector.is_scanning})

@app.route('/api/get_alerts')
def get_alerts():
    return jsonify({
        "alerts": list(detector.alerts),
        "is_scanning": detector.is_scanning,
        "is_injecting": rogue_ap.is_running,
        "queue_size": packet_queue.qsize(),
        "aps_tracked": len(detector.detected_aps)
    })

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    detector.clear_alerts()
    return jsonify({"status": "Log Cancellati"})

@app.route('/api/reset_tracking', methods=['POST'])
def reset_tracking():
    detector.detected_aps.clear()
    detector.alerts = []
    detector.alert_counter = 0
    return jsonify({"status": "Tracking resettato"})

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0', use_reloader=False)
