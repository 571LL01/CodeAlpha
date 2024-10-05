#!/bin/env python3

from collections import Counter, defaultdict
from ipaddress import ip_address, ip_network
import scapy.all as scapy
import requests
from rich.console import Protocol, Screen, Console
from rich.table import Table
import time

console = Console()


def is_internal_ip(ip):
    private_networks = [
        ip_network('10.0.0.0/8'),
        ip_network('172.16.0.0/12'),
        ip_network('192.168.0.0/16'),
        ip_network('127.0.0.0/8')  # Loopback
    ]
    ip_obj = ip_address(ip)
    return any(ip_obj in net for net in private_networks)


# Fonction pour obtenir des informations sur l'adresse IP via une API publique
def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=7)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "hostname": data.get("hostname", "N/A"),
                "city": data.get("city", "N/A"),
                "region": data.get("region", "N/A"),
                "country": data.get("country", "N/A"),
                "loc": data.get("loc", "N/A"),
                "org": data.get("org", "N/A"),
                
            }
        else:
            return {"error": "API request failed"}
    except requests.exceptions.Timeout:
        return {"error" : "Request timed out"}
    except Exception as e:
        return {"error": str(e)}

# fonction utiliser pour afficher le packet reseau directement en live 
def print_info(packet):
    print(packet.summary())
    if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src 
            ip_dst = packet[scapy.IP].dst   
            protocol = packet[scapy.IP].proto

            # Detection des attaques DOS et brute force ssh 
            detect_ddos_attack(ip_src)
            detect_ssh_brute_force(ip_src, packet)




# Analyse des paquets pour compter les IP sourcese
def analyze_packets(packets):

    ip_addresses = []
    results = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src 
            ip_dst = packet[scapy.IP].dst   
            protocol = packet[scapy.IP].proto  

            # Obtenir les ports TCP ou UDP si disponibles
            if packet.haslayer(scapy.TCP):
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport
                proto_str = "TCP"
            elif packet.haslayer(scapy.UDP):
                sport = packet[scapy.UDP].sport
                dport = packet[scapy.UDP].dport
                proto_str = "UDP"
            else:
                sport, dport = "N/A", "N/A"
                proto_str = "Other"
            ip_addresses.append((ip_src, sport, proto_str))
    
    ip_counter = Counter([x[0] for x in ip_addresses])

    # Créer un tableau avec rich
    # Créer un tableau avec rich
    table = Table(title="Analyse des IP et protocoles")
    table.add_column("IP", justify="left", style="cyan")
    table.add_column("Requêtes", justify="right", style="magenta")
    table.add_column("Type", justify="center", style="green")
    table.add_column("Protocole", justify="left", style ="blue")
    table.add_column("Port source", justify="right", style="red")
    table.add_column("Infos", justify="left", style="yellow")

    #Affichage des resultats 
    for ip, count in ip_counter.items():
        internal = is_internal_ip(ip)
        ip_type = "Interne" if internal else "Externe"

        if not internal: # Obtenir des infos géographiques uniquement pour les IPs externes 
            ip_info = get_ip_info(ip)
            info = f"Ville: {ip_info['city']}, Pays: {ip_info['country']}, Organisation: {ip_info['org']}"
        else:
            info= "N/A"
        # Ajouter une ligne au tableau
        table.add_row(ip, str(count), ip_type, proto_str,str(sport) , info)
        table.add_row("", "", "", "")  # Ajouter une ligne vide pour l'espacement

        results.append((ip, count, ip_type,proto_str ,sport , info))

    console.print(table) # Afficher le tableau 
    
    # Enregistrement des resultats dans un fichier .csv
    with open("ip_analyse_resultat.csv", "w") as f:

        f.write("IP,Requêtes,Type,Infos\n")  # En-tête
        for ip, count, ip_type,proto_str, sport, info in results:
            f.write(f"{ip},{count},{ip_type}, {proto_str}, {sport}, ,{info}\n")

# Dictionnaire pour stocker les requêtes par IP et leur temps
request_log = defaultdict(lambda: {"count": 0, "first_seen": time.time()})

# Durée de la fenêtre temporelle en secondes (par exemple, 60 secondes)
TIME_WINDOW = 60  
MAX_REQUESTS = 100  # Seuil pour la détection d'une attaque

def detect_ddos_attack(ip):
    current_time = time.time()

    # Si l'IP a déjà été enregistrée, on met à jour ses informations
    if ip in request_log:
        log = request_log[ip]
        log["count"] += 1

        # Si le temps écoulé dépasse la fenêtre de temps, réinitialiser le compteur
        if current_time - log["first_seen"] > TIME_WINDOW:
            log["count"] = 1
            log["first_seen"] = current_time

        # Si le nombre de requêtes dépasse le seuil dans la fenêtre de temps
        if log["count"] > MAX_REQUESTS:
            console.print(f"[bold red]ALERT: Possible DoS attack from IP {ip} with {log['count']} requests in {TIME_WINDOW} seconds.[/bold red]")
            #send_alert(ip, log["count"])
            log["count"] = 0  # Réinitialiser après l'alerte
    else:
        # Nouvelle IP, initialiser ses informations
        request_log[ip] = {"count": 1, "first_seen": current_time}

# Dictionnaire pour suivre les tentatives SSH par IP
ssh_attempts = defaultdict(lambda: {"count_ssh": 0, "first_seen": time.time()})

# Paramètres de la fenêtre temporelle pour la détection de brute force SSH
TIME_WINDOW_SSH = 60  # Durée de la fenêtre en secondes
SSH_THRESHOLD = 10  # Nombre de tentatives pour déclencher une alerte

def detect_ssh_brute_force(ip, packet):
    current_time = time.time()

    # Vérifie si c'est une tentative SSH (port 22, TCP)
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 22:
        log = ssh_attempts[ip]
        log["count_ssh"] += 1

        # Si la fenêtre de temps est dépassée, réinitialiser le compteur
        if current_time - log["first_seen"] > TIME_WINDOW_SSH:
            log["count_ssh"] = 1
            log["first_seen"] = current_time

        # Si le nombre de tentatives dépasse le seuil
        if log["count_ssh"] > SSH_THRESHOLD:
            console.print(f"[bold red]ALERT: Possible SSH brute force attack from IP {ip}. {log['count_ssh']} attempts in {TIME_WINDOW_SSH} seconds.[/bold red]")
            # send_alert(ip, log["count_ssh"])
            log["count_ssh"] = 0  # Réinitialiser après l'alerte

def save_capture_to_pcap(packets):
    scapy.wrpcap("Capture.pcap", packets)
    print("Capture saved to caputure.pcap")



if __name__ == '__main__':

    try:

        print(scapy.get_if_list()) # permet de lister les interfaces reseaux sur la machine
        interface_name = input("Spécifiez l'interface réseau à sniffer (par ex : wlan0) : ")

        filters = "icmp or udp port 53 or tcp port 80 or tcp port 22"  # ICMP, DNS (UDP 53), HTTP (TCP 80), SSH (TCP 22)
        p = scapy.sniff(count=100, iface=interface_name, filter=filters, prn=print_info)

        # Analyser un fichier de capture réseau 
        #p = scapy.rdpcap("./web.pcap")
        analyze_packets(p)
        save_capture_to_pcap(p)
        # p.summary()  # utiliser pour afficher la capture reseau une fois le sniff fini
    except Exception as e:
        print(f"Erreur: {e}")