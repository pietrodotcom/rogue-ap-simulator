# Usa un'immagine base di Python leggera
FROM python:3.9-slim

# Imposta la cartella di lavoro dentro il container
WORKDIR /rogue_project

# Installa tcpdump/libpcap (serve a Scapy anche per finta)
RUN apt-get update && apt-get install -y libpcap-dev tcpdump && rm -rf /var/lib/apt/lists/*

# Copia il file dei requisiti e installa le dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia tutto il resto del codice nel container
COPY . .

# Indica che il container userà la porta 5000
EXPOSE 5000

# Il comando per avviare l'app
CMD ["python", "app.py"]