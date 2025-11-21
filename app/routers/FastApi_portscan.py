#!/usr/bin/env python3
import pyfiglet
import socket
import subprocess
from datetime import datetime
from contextlib import closing
import tempfile

from fastapi import APIRouter, Request, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# --------------------------
#   FUNCIONES INTERNAS
# --------------------------

def buscar_destino(pcap_file: str, ip_busqueda: str) -> bool:
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "icmp.type == 8",
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
    start = 1
    end = 65535
    timeout = 0.8
    open_ports = []

    for port in range(start, end + 1):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip_port, port))
            if result == 0:
                open_ports.append(port)

    return open_ports


# --------------------------
#   RUTA HTML (GET)
# --------------------------
@router.get("/op_portscan", response_class=HTMLResponse, tags=["op_portscan"])
async def cargar_pagina_portscan(request: Request):
    return templates.TemplateResponse("portscan.html", {"request": request})


# --------------------------
#   RUTA POST (API)
# --------------------------
@router.post("/op_portscan", tags=["op_portscan"])
async def ejecutar_portscan(
    pcap: UploadFile = File(...),
    indice_destino: int = Query(0, ge=0)
):
    """Recibe un PCAP y devuelve la IP analizada y sus puertos abiertos"""
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            contenido = await pcap.read()
            tmp.write(contenido)
            tmp_path = tmp.name
    except:
        raise HTTPException(500, "Error guardando el archivo temporal.")

    ip_busqueda = indice_destino

    try:
        destino = buscar_destino(tmp_path, ip_busqueda)
        banner(destino)
        return {
            "Ip": destino,
            "Puertos Abiertos": PortScan(destino)
        }
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        try:
            import os
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass
