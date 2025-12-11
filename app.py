from flask import Flask, render_template, request, jsonify
from models.simulator_model import RogueAPModel
from models.detector_model import DetectorModel
import threading
import time
import datetime

app = Flask(__name__)

# Istanziamo i Modelli
rogue_ap = RogueAPModel()
detector = DetectorModel()

# --- SIMULAZIONE ---
def detector_loop():
    print("[SYSTEM] Thread Detector avviato...")
    while True:
        if detector.is_scanning:
            # Creiamo un finto alert ogni 2 secondi per testare la UI
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            fake_alert = f"[{timestamp}] ALERT: Rilevato Rogue AP (Simulazione) - MAC: 00:00:00:BAD:MAC"
            
            # Forziamo l'inserimento nell'alert list del modello
            # (In produzione questo lo farebbe analyze_packet)
            if fake_alert not in detector.alerts:
                detector.alerts.append(fake_alert)
                print(f"[DEBUG] Generato alert: {fake_alert}") # Se vedi questo, Python funziona
            
            # Manteniamo la lista pulita (ultimi 10 messaggi)
            if len(detector.alerts) > 10:
                detector.alerts.pop(0)
                
            time.sleep(2) 
        else:
            time.sleep(1)

# Avvio thread background
t = threading.Thread(target=detector_loop)
t.daemon = True
t.start()

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/start_sim', methods=['POST'])
def start_sim():
    data = request.json
    rogue_ap.configure(data.get('ssid'), data.get('bssid'), "High", data.get('interval'))
    rogue_ap.start_attack()
    return jsonify({"status": "Attacco Avviato"})

@app.route('/api/stop_sim', methods=['POST'])
def stop_sim():
    rogue_ap.stop_attack()
    return jsonify({"status": "Attacco Fermato"})

@app.route('/api/toggle_detector', methods=['POST'])
def toggle_detector():
    status = request.json.get('status')
    print(f"[DEBUG] Switch premuto. Stato ricevuto: {status}")
    if status == 'on':
        detector.is_scanning = True
    else:
        detector.is_scanning = False
    return jsonify({"status": "Ok"})

@app.route('/api/get_alerts')
def get_alerts():
    # Restituisce la lista al frontend (JavaScript)
    return jsonify({"alerts": list(detector.alerts)})

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    detector.clear_alerts() # Chiama il metodo del Model che abbiamo appena creato
    return jsonify({"status": "Log Cancellati"})

if __name__ == '__main__':
    # Disabilita il reloader automatico per non sdoppiare i thread
    app.run(debug=True, port=5000, host='0.0.0.0', use_reloader=False)