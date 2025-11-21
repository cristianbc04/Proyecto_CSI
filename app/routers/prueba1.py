import subprocess
import sys
import socket
from datetime import datetime
from contextlib import closing
import scapy.all as scapy
from scapy.all import conf, get_if_addr


def get_MAC(ip_ataque: str, interfaz: str):
    arp_request = scapy.ARP(pdst = ip_ataque)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")   
    arp_request_broadcast = broadcast / arp_request
    ans, _ = scapy.srp(arp_request_broadcast, iface=interfaz, timeout=3, verbose=False)
    if len(ans) == 0:
        return "⚠️  Sin respuesta ARP (verifica firewall, IP o permisos)"
    else:
        return ans[0][1].hwsrc
    """
    hostname = socket.gethostname()
    ip_host = socket.gethostbyname(hostname)
    """

def main():
    ip_host = "192.168.1.158"
    interfaz = r"\Device\NPF_{4C19F751-9A06-4B55-B1EA-C49F268FC666}"  # usa el nombre exacto de tu salida anterior
    print("Mi IP real es:", ip_host)
    print("La IP de la maquina es: " + get_MAC(ip_host, interfaz))


if __name__ == "__main__":  
    main()