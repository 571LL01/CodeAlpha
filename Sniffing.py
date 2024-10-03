#!/bin/env python3

from collections import Counter
from ipaddress import ip_address, ip_network
import scapy.all as scapy
import requests
from rich.console import Console
from rich.table import Table

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
        response = requests.get(f"https://ipinfo.io/{ip}/json")
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
    except Exception as e:
        return {"error": str(e)}

# fonction utiliser pour afficher le packet reseau directement en live 
def print_info(packet):
    print(packet.summary())


# Analyse des paquets pour compter les IP sourcese
def analyze_packets(packets):

    ip_addresses = []
    results = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_addresses.append(packet[scapy.IP].src)
    
    ip_counter = Counter(ip_addresses)

    # Créer un tableau avec rich
    # Créer un tableau avec rich
    table = Table(title="Analyse des IP")
    table.add_column("IP", justify="left", style="cyan")
    table.add_column("Requêtes", justify="right", style="magenta")
    table.add_column("Type", justify="center", style="green")
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
        table.add_row(ip, str(count), ip_type, info)
        table.add_row("", "", "", "")  # Ajouter une ligne vide pour l'espacement

        results.append((ip, count, ip_type, info))

    console.print(table) # Afficher le tableau 
    
    # Enregistrement des resultats dans un fichier .csv
    with open("ip_analyse_resultat1.csv", "w") as f:
m
        f.write("IP,Requêtes,Type,Infos\n")  # En-tête
        for ip, count, ip_type, info in results:
            f.write(f"{ip},{count},{ip_type},{info}\n")



if __name__ == '__main__':

    try:

        print(scapy.get_if_list()) # permet de lister les interfaces reseaux sur la machine
        interface_name = input("Spécifiez l'interface réseau à sniffer (par ex : wlan0) : ")

        # interface_name = 'wlan0' # spécifier l'inface reseau à sniffer 
        p = scapy.sniff(count=100, iface=interface_name, prn=print_info)

        # Analyser un fichier de capture réseau 
        #p = scapy.rdpcap("./web.pcap")
        analyze_packets(p)
        # p.summary()  # utiliser pour afficher la capture reseau une fois le sniff fini
    except Exception as e:
        print(f"Erreur: {e}")