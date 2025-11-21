#!/usr/bin/env python3
import ipaddress
import os
import re
import subprocess
import tempfile
from typing import List, Dict

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from scapy.all import IP, UDP, Raw, wrpcap

# ----------------------------------------
#  Configuración / constantes
# ----------------------------------------

default_packet_count = 50
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ----------------------------------------
#  Funciones auxiliares (adaptadas de tu script)
# ----------------------------------------

def extraer_destinos(pcap_file: str) -> List[str]:
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
        raise RuntimeError(f"No se pudo ejecutar tshark: {e}") from e


def procesar_lineas_con_mensaje(lineas: List[str]) -> List[Dict]:
    resultados = []
    for linea in lineas:
        campos = linea.strip().split('\t')
        if len(campos) < 3:
            continue
        ip_src = campos[0].strip()
        ip_dst = campos[1].strip()
        mensaje = campos[2].strip()
        if not ip_src or not ip_dst or not mensaje:
            continue
        resultados.append({
            'ip_src': ip_src,
            'ip_dst': ip_dst,
            'mensaje': mensaje
        })
    return resultados


def extraer_mensajes(pcap_file: str) -> List[Dict]:
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
        raise RuntimeError(f"No se pudo extraer mensajes de {pcap_file}: {e}") from e


def es_ip_valida(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def convertir_payload(mensaje: str) -> bytes:
    msg = mensaje.replace(':', '').replace(' ', '')
    if HEX_RE.match(msg) and len(msg) % 2 == 0:
        try:
            return bytes.fromhex(msg)
        except Exception:
            pass
    return mensaje.encode('latin1', errors='replace')


def ataques_con_mensaje(
    datos: List[Dict],
    target_ip: str,
    packet_count: int = default_packet_count,
    output_path: str = "salida.pcap",
) -> int:
    nuevo_paquete = []

    origenes = {d['ip_src'] for d in datos if d.get('ip_src')}
    if not origenes:
        raise RuntimeError("No se encontraron IP origen en los datos extraídos.")

    payloads_por_src = {}
    for d in datos:
        src = d['ip_src']
        if src not in payloads_por_src and d.get('mensaje'):
            payloads_por_src[src] = d['mensaje']

    default_payload = b'LAB_PAYLOAD'

    for src in origenes:
        if not es_ip_valida(src):
            # simplemente lo saltamos, no petamos todo
            continue

        payload_hex = None
        for d in datos:
            if d['ip_src'] == src and d['ip_dst'] == target_ip and d.get('mensaje'):
                payload_hex = d['mensaje']
                break

        if payload_hex is None:
            payload_hex = payloads_por_src.get(src)

        if payload_hex is None:
            payload_bytes = default_payload
        else:
            payload_bytes = convertir_payload(payload_hex)

        for i in range(packet_count):
            pkt = IP(src=src, dst=target_ip) / UDP(sport=12345, dport=12345) / Raw(load=payload_bytes)
            pkt.time = i * 0.0001
            nuevo_paquete.append(pkt)

    if not nuevo_paquete:
        raise RuntimeError("No se generó ningún paquete. Revisa que tshark haya extraído mensajes UDP con payload.")

    wrpcap(output_path, nuevo_paquete)
    return len(nuevo_paquete)

# ----------------------------------------
#  Endpoints FastAPI
# ----------------------------------------

@router.get("/op_ddos", response_class=HTMLResponse, tags=["op_ddos"])
async def cargar_pagina_portscan(request: Request):
        return templates.TemplateResponse("ddos.html", {"request": request})


@router.post("/op_ddos", response_class=FileResponse, tags=["op_ddos"])
async def mutar_pcap(
    pcap: UploadFile = File(..., description="Archivo PCAP de entrada"),
    indice_destino: int = Query(0, ge=0, description="Índice de IP destino a usar"),
    packet_count: int = Query(default_packet_count, ge=1, le=10000, description="Paquetes por IP origen"),
):
    """Recibe un pcap, genera un nuevo pcap 'de ataque' y lo devuelve."""

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
            packet_count=packet_count,
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
