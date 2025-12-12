#!/usr/bin/env python3
import ipaddress
import os
import re
import subprocess
import tempfile
from typing import List, Dict

from fastapi import UploadFile, File, HTTPException, Query, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from scapy.all import IP, UDP, Raw, wrpcap


# ======================================================
#  Configuración y constantes
# ======================================================

DEFAULT_PACKET_COUNT = 50
HEX_PAYLOAD_REGEX = re.compile(r"^[0-9a-fA-F]+$")

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ======================================================
#  Funciones auxiliares
# ======================================================

def is_valid_ip(address: str) -> bool:
    """Comprueba si una IP es válida."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def hex_or_text_to_bytes(payload: str) -> bytes:
    """
    Convierte un payload hexadecimal a bytes si es válido.
    Si no, devuelve el texto codificado.
    """
    clean = payload.replace(":", "").replace(" ", "")

    if HEX_PAYLOAD_REGEX.fullmatch(clean) and len(clean) % 2 == 0:
        try:
            return bytes.fromhex(clean)
        except ValueError:
            pass

    return payload.encode("latin1", errors="replace")


# ======================================================
#  Extracción de información desde PCAP
# ======================================================
def extract_destinations(pcap_path: str) -> List[str]:
    """
    Extrae IPs destino únicas de tráfico UDP usando tshark.
    Mantiene el orden de aparición.
    """
    
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.dst",
        "udp",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error ejecutando tshark: {e}") from e

    destinations: List[str] = []
    seen = set()

    for line in result.stdout.splitlines():
        ip = line.strip()
        if ip and ip not in seen:
            seen.add(ip)
            destinations.append(ip)

    return destinations


def parse_message_lines(lines: List[str]) -> List[Dict[str, str]]:
    """
    Procesa líneas tshark con formato:
    ip.src \t ip.dst \t data.data
    """
    
    parsed = []
    for line in lines:
        fields = line.strip().split("\t")
        if len(fields) < 3:
            continue

        src_ip, dst_ip, message = map(str.strip, fields[:3])
        if not (src_ip and dst_ip and message):
            continue

        parsed.append({
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "message": message,
        })

    return parsed


def extract_udp_messages(pcap_path: str) -> List[Dict[str, str]]:
    """Extrae mensajes UDP (payload) desde un PCAP usando tshark."""
    
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "data.data",
        "udp",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"No se pudieron extraer mensajes UDP: {e}") from e

    return parse_message_lines(result.stdout.splitlines())


# ======================================================
#  Generación de tráfico "de ataque"
# ======================================================

def generate_attack_pcap(
    extracted_data: List[Dict[str, str]],
    target_ip: str,
    packet_count: int,
    output_path: str,
) -> int:
    """
    Genera un PCAP con tráfico UDP repetitivo hacia una IP destino,
    reutilizando payloads observados.
    """
    
    packets = []
    default_payload = b"LAB_PAYLOAD"

    source_ips = {
        entry["ip_src"]
        for entry in extracted_data
        if is_valid_ip(entry.get("ip_src", ""))
    }

    if not source_ips:
        raise RuntimeError("No se encontraron IPs origen válidas.")

    # Primer payload observado por cada IP origen
    payload_by_src = {}
    for entry in extracted_data:
        src = entry["ip_src"]
        if src not in payload_by_src and entry.get("message"):
            payload_by_src[src] = entry["message"]

    for src_ip in source_ips:
        payload_hex = next(
            (
                d["message"]
                for d in extracted_data
                if d["ip_src"] == src_ip and d["ip_dst"] == target_ip
            ),
            payload_by_src.get(src_ip),
        )

        payload_bytes = (
            hex_or_text_to_bytes(payload_hex)
            if payload_hex
            else default_payload
        )

        for i in range(packet_count):
            pkt = (
                IP(src=src_ip, dst=target_ip)
                / UDP(sport=12345, dport=12345)
                / Raw(load=payload_bytes)
            )
            pkt.time = i * 0.0001
            packets.append(pkt)

    if not packets:
        raise RuntimeError("No se generaron paquetes UDP.")

    wrpcap(output_path, packets)
    return len(packets)


# ======================================================
#  Endpoints FastAPI
# ======================================================

@router.get("/op_ddos", response_class=HTMLResponse, tags=["op_ddos"])
async def ddos_page(request: Request):
    return templates.TemplateResponse("ddos.html", {"request": request})


@router.post("/op_ddos", response_class=FileResponse, tags=["op_ddos"])
async def ddos_execute(
    pcap: UploadFile = File(..., description="Archivo PCAP de entrada"),
    destination_index: int = Query(0, ge=0, description="Índice de IP destino"),
    packet_count: int = Query(
        DEFAULT_PACKET_COUNT,
        ge=1,
        le=10000,
        description="Paquetes por IP origen",
    ),
):
    # Guardar PCAP de entrada
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(await pcap.read())
            input_path = tmp.name
    except Exception:
        raise HTTPException(500, "No se pudo guardar el PCAP de entrada")

    # Archivo de salida
    out_fd, output_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)

    try:
        destinations = extract_destinations(input_path)
        if not destinations:
            raise HTTPException(400, "No se encontraron IP destino en el PCAP")

        if destination_index >= len(destinations):
            raise HTTPException(
                400,
                {
                    "error": "Índice fuera de rango",
                    "destinos": destinations,
                },
            )

        target_ip = destinations[destination_index]
        extracted_data = extract_udp_messages(input_path)

        packet_total = generate_attack_pcap(
            extracted_data,
            target_ip,
            packet_count,
            output_path,
        )

        return FileResponse(
            output_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=f"ataque_{target_ip.replace('.', '_')}.pcap",
        )

    except RuntimeError as e:
        raise HTTPException(500, str(e))

    finally:
        if os.path.exists(input_path):
            os.remove(input_path)
