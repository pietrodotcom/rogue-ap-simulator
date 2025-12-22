FROM python:3.9-slim

WORKDIR /rogue_project

# Installazione dipendenze di sistema (tcpdump e libpcap per Scapy)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]