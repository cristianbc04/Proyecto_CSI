import pyfiglet
import subprocess
import sys
import socket
from datetime import datetime
from contextlib import closing
from scapy.all import rdpcap, ICMP, IP

def buscar_destino(pcap_file: str, ip_busqueda: str) -> bool:
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "icmp.type == 8",  # ICMP Echo Request (ping saliente)
        "-T", "fields", "-e", "ip.dst",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    ips = [l.strip() for l in res.stdout.splitlines() if l.strip()]
    
    return ip_busqueda in ips

def banner(target):
    ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
    print(ascii_banner) 
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)

def PortScan(ip_port):
    ports = [139, 445]
    open_ports = []
    timeout = 0.8

    for port in ports:
        # crear y cerrar el socket en cada iteración para no agotar descriptores
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip_port, port))
            if result == 0:
                print(f"[+] Port {port} is open")
                open_ports.append(port)

    return open_ports

def main():
    if len(sys.argv) != 3:
        print("No se puede hacer el PortScan, falta argumentos (captura de trafico y/o indice de la ip)")
        sys.exit(1) 
        
    archivo_pacp = sys.argv[1]
    ip_busqueda = sys.argv[2]
    if not buscar_destino(archivo_pacp, ip_busqueda):
        print("[!] La ip que has puesto no se encuentra en el archivo o no es tipo icmp")
    else: 
        banner(ip_busqueda)
        resultado = PortScan(ip_busqueda)

if __name__ == '__main__':
    main()