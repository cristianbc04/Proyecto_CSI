import os
import subprocess
import sys
import re
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, ICMP
import scapy.all as scapy
import tempfile
from typing import List, Dict

from fastapi import FastAPI, Form, UploadFile, File, HTTPException, Query, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")
router = APIRouter()
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

ip_atacante = "172.16.0.10" # el rango se va a hacer en 172.16.0.0/24
mac_atacante = "00:11:22:33:44:55"
dns = "Suplantacion.es"

# en esta funcion se va a generar el mesnaje que simula el ataque
def mensaje_ataque(mac_victima: str):
    victim_bytes = bytes.fromhex(mac_victima.replace(":", ""))

    dhcp_discover = Ether(src=mac_victima, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0", dst="255.255.255.255") / \
        UDP(sport=68, dport=67) / \
        BOOTP(op=1, chaddr=victim_bytes) / \
        DHCP(options=[("message-type", "discover"), "end"])

    dhcp_offer = Ether(src=mac_atacante, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src=ip_atacante, dst="255.255.255.255") / \
        UDP(sport=67, dport=68) / \
        BOOTP(op=2, yiaddr="172.16.0.11", siaddr=ip_atacante, chaddr=victim_bytes) / \
        DHCP(options=[
            ("message-type", "offer"),
            ("server_id", ip_atacante),
            ("subnet_mask", "255.255.255.0"),
            ("router", ip_atacante),
            ("domain-name-server", dns),
            ("lease_time", 3600),
            "end"
        ])

    return dhcp_offer, dhcp_discover

def suplantacion_dhcp(mac_victima: str):
    
    payload_oferta, payload_discover = mensaje_ataque(mac_victima=mac_victima)
    packets = [payload_discover, payload_oferta]
    for _ in range(5):
        mensaje_icmp = Ether(src=mac_victima, dst=mac_atacante) / \
               IP(src="172.16.0.11", dst="172.16.0.10") / ICMP()
        packets.append(mensaje_icmp)
        
    return packets
        

@router.get("/op_rogue", response_class=HTMLResponse, tags=["op_rogue"])
async def cargar_pagina_rogue(request: Request):
    return templates.TemplateResponse("rogue.html", {"request": request})

@router.post("/op_rogue", response_class=HTMLResponse, tags=["op_rogue"])
async def cargar_pagina_rogue(
    mac_victima: str = Form(..., description="MAC víctima")
):
    if not mac_victima:
        raise HTTPException(status_code=400, detail="Debe introducir una MAC válida.")

    out_fd, out_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)
    
    try:
        paquetes = suplantacion_dhcp(mac_victima)
        
        if not paquetes:
            raise HTTPException(status_code=400, detail="No se generaron paquetes.")
            
        scapy.wrpcap(out_path, paquetes)
        
        return FileResponse(
            out_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=f"rogue.pcap",
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    