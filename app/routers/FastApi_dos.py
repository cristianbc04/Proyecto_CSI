#!/usr/bin/env python3
import ipaddress
import os
import re
import subprocess
import tempfile
from typing import List, Dict
import socket
import random

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from scapy.all import IP, UDP, Raw, wrpcap

# Número de paquetes por IP origen para el ataque
default_packet_count = 50

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

# variables exclusivas de la API
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def extraer_destinos(pcap_file: str) -> list:
    cmd = [
        "tshark", "-r", pcap_file,
        "-T", "fields", "-e", "ip.dst",
        "udp"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        ips = [l.strip() for l in res.stdout.splitlines() if l.strip()]
        destinos, vistos = [], set()
        for ip in ips:
            if ip not in vistos:
                vistos.add(ip)
                destinos.append(ip)
        return destinos
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] No se pudo ejecutar tshark: {e}")

def procesar_lineas_con_mensaje(lineas: list) -> list:
    resultados = []
    for linea in lineas:
        campos = linea.strip().split('\t')
        # esperamos 3 campos: ip.src, ip.dst, data.data
        if len(campos) < 3:
            continue
        ip_src = campos[0].strip()
        ip_dst = campos[1].strip()
        mensaje = campos[2].strip()
        # saltar si falta alguno
        if not ip_src or not ip_dst or not mensaje:
            continue
        resultados.append({
            'ip_src': ip_src,
            'ip_dst': ip_dst,
            'mensaje': mensaje
        })
    return resultados

def extraer_mensajes(pcap_file: str) -> list:
    cmd = [
        "tshark", "-r", pcap_file,
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "data.data",
        "udp"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lineas = res.stdout.splitlines()
        return procesar_lineas_con_mensaje(lineas)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] No se pudo extraer mensajes de {pcap_file}: {e}")

def es_ip_valida(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def convertir_payload(mensaje: str) -> bytes:
    """
    Convierte el campo data.data (hex) a bytes.
    Si no parece hex válido, cae a interpretarlo como ASCII/latin1.
    """
    # data.data de tshark viene normalmente como hex sin espacios: "48656c6c6f"
    msg = mensaje.replace(':', '').replace(' ', '')  # por si hay ':' o espacios
    if HEX_RE.match(msg) and len(msg) % 2 == 0:
        try:
            return bytes.fromhex(msg)
        except Exception:
            pass
    # fallback: devolver bytes del string (latin1 para mantener 0-255)
    return mensaje.encode('latin1', errors='replace')

def ataques_con_mensaje(
    datos: list,
    target_ip: str,
    packet_count: int = default_packet_count,
    output_path: str = "salida_DoS.pcap",
) -> int:
    """
    Genera paquetes UDP con scapy y los guarda en output_path.
    Devuelve el número de paquetes generados.
    """
    nuevo_paquete = []

    # Orígenes únicos en los datos
    origenes = {d['ip_src'] for d in datos if d.get('ip_src')}
    print(f"[debug] Orígenes únicos en el pcap (datos): {len(origenes)}")

    if not origenes:
        print("[!] No se encontraron IP origen en los datos extraídos.")
    
    elemet_index = random.randrange(0, len(origenes))
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    element_random = list(origenes)[elemet_index]

    datos_DOS = []
    default_payload = b'LAB_PAYLOAD'  # payload por defecto

    for ip in (element_random, IPAddr):
        if any(entry['ip'] == ip for entry in datos_DOS):
            continue
        if es_ip_valida(ip):
            datos_DOS.append({'ip': ip, 'payload': default_payload})
        else:
            print(f"[!] IP inválida descartada: {ip}")

    if not datos_DOS:
        print("[!] No hay orígenes válidos (aleatorio y/o local).")
        return 0

    for d in datos_DOS:
        for i in range(packet_count):
            pkt = IP(src=d['ip'], dst=target_ip) / UDP(sport=12345, dport=12345) / Raw(load=d['payload'])
            pkt.time = i * 0.0001
            nuevo_paquete.append(pkt)

            if (i < 3) or ((i + 1) % 10 == 0) or (i == packet_count - 1):
                print(f"Generando {i+1}/{packet_count}: {d['ip']} → {target_ip}")

    if not nuevo_paquete:
        print("[!] No se generó ningún paquete.")
        return 0

    # 🟢 Guardar en el output_path que le pasamos
    wrpcap(output_path, nuevo_paquete)
    print(f"[✔] pcap de ataque guardado en: {output_path} (paquetes: {len(nuevo_paquete)})")

    return len(nuevo_paquete)

@router.get("/op_dos", response_class=HTMLResponse, tags=["op_dos"])
async def cargar_pagina_html(request: Request):
    return templates.TemplateResponse("dos.html", {"request": request})

@router.post("/op_dos", tags=["op_dos"])
async def ejecutar_portscan(
    pcap: UploadFile = File(...),
    indice_destino: int = Query(0, ge=0)
):
    # Guardar el pcap subido en un archivo temporal
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            contenido = await pcap.read()
            tmp.write(contenido)
            tmp_path = tmp.name
    except Exception:
        raise HTTPException(status_code=500, detail="No se pudo guardar el archivo PCAP temporal.")

    # Crear archivo de salida temporal
    out_fd, out_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)
    
    try:
        destinos = extraer_destinos(tmp_path)
        if not destinos:
            raise HTTPException(status_code=400, detail="No se encontraron IP destino en el PCAP.")

        if indice_destino < 0 or indice_destino >= len(destinos):
            detalle = {
                "error": "Índice fuera de rango",
                "indices_validos": list(range(len(destinos))),
                "destinos": destinos,
            }
            raise HTTPException(status_code=400, detail=detalle)

        target_ip = destinos[indice_destino]

        datos = extraer_mensajes(tmp_path)

        total_paquetes = ataques_con_mensaje(
            datos,
            target_ip,
            packet_count=default_packet_count,
            output_path=out_path,
        )

        if total_paquetes == 0:
            raise HTTPException(status_code=400, detail="No se generaron paquetes.")

        # Devolvemos el archivo generado
        return FileResponse(
            out_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=f"ataque_{target_ip.replace('.', '_')}.pcap",
        )

    except RuntimeError as e:
        # errores de nuestra lógica
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # limpiar el pcap de entrada; el de salida lo borrará el sistema después de servirlo (según cómo despliegues)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

