
Rogue Access Point Simulator + Detection Tool

Un piccolo ecosistema per studiare l’attacco e la difesa.

 Modulo 1: Simulatore Rogue AP
		interfaccia per configurare SSID fake, beacon intervals, channel hopping
		generazione di traffico simulato (non reale, basta imitare pacchetti con scapy)

 Modulo 2: Rilevatore
		algoritmo che riconosce gli AP generati dal simulatore
		misure comparative:
		differenze negli interarrivi dei beacon
		rilevazione bad mac
		channel hopping sospetto


Breve spiegazione del codice

simulator_model.py
	fz configure e _build_packet: configurazione iniziale e costruzione del beacon
	_beacon_loop: costruzione della coda dei beacon
	fz di start e stop attack

detector_model.py
	analyze_packet, _extract_channel: per estrazione dei dati dall'ap
	_check_heuristics: implementazione della logica di controllo degli ap:
		fake mac per ap con bssid che inizia per 00:00:00
		channel hopping per gli ap che cambiano canale
		beacon interval anomalo (beacon con piccolo tempo di interarrivo = anomalo)
	**memorizziamo gli ap in detected_aps
	_trigger_alert: generazione degli alert, visualizzazione massima di 25 thread (i più recenti volta per volta)
	clear_alerts svuotiamo gli alert mantenendo il tracking

app.py
	definizione routes

dashboard.html 
	frontend: inserimento ssid, bssid, canale, beacon interval
			  attivazione atk injection start/stop
			  toggle per attivazione o meno del detector
			  possibile pulire la vista 

How to e Casi d'uso

Inserire il ssid target, bssid spoofed, canale e beacon interval a proprio piacimento
-Inject beacon e poi il bottone active scanning (l'ordine non è importante)
-Per terminare l'attacco premere su stop, (eventualmente spegnere l'active scanning)
-Per iniziare un nuovo attacco (volendo quindi modificare uno fra i parametri modificabili) è necessario stoppare il corrente attacco, modificare i parametri, e cliccare su inject beacon.

Ecco i vari casi in cui verrà rilevato l'ap malevolo sul frontend:
-inserendo un mac che inizia per 00:00:00 (bad mac)
-eseguire una beacon injection su un canale x, stoppare l'injection, modificare il canale e restartare l'injection (channel hopping)
-inserendo un basso beacon interval (ad esempio con 0.1s avremo una segnalazione, con 1s no)
