#!/usr/bin/env python3
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import random
from typing import List, Dict

from app.utils.render import render_form_error
from fastapi import UploadFile, File, Query, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from scapy.all import IP, UDP, Raw, wrpcap


# ======================================================
#  Configuración / constantes
# ======================================================

DEFAULT_PACKET_COUNT = 50
HEX_PAYLOAD_REGEX = re.compile(r"^[0-9a-fA-F]+$")

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ======================================================
#  Funciones internas
# ======================================================

def extract_destinations(pcap_path: str) -> List[str]:
    """Obtiene las IP destino únicas desde un PCAP (tráfico UDP)."""
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
        raise RuntimeError(f"No se pudo ejecutar tshark: {e}") from e

    destinations = []
    seen = set()

    for line in result.stdout.splitlines():
        ip = line.strip()
        if ip and ip not in seen:
            seen.add(ip)
            destinations.append(ip)

    return destinations


def parse_message_lines(lines: List[str]) -> List[Dict[str, str]]:
    """
    Procesa líneas de tshark con formato:
    ip.src \\t ip.dst \\t data.data
    """
    parsed = []

    for line in lines:
        fields = line.strip().split("\t")
        if len(fields) < 3:
            continue

        src_ip, dst_ip, payload = map(str.strip, fields[:3])
        if not (src_ip and dst_ip and payload):
            continue

        parsed.append({
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "payload": payload,
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


def is_valid_ip(address: str) -> bool:
    """Comprueba si una IP tiene un formato válido."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def payload_to_bytes(payload: str) -> bytes:
    """
    Convierte un payload en formato string a bytes.
    Si es hexadecimal válido, se decodifica; si no, se trata como texto.
    """
    clean = payload.replace(":", "").replace(" ", "")

    if HEX_PAYLOAD_REGEX.fullmatch(clean) and len(clean) % 2 == 0:
        try:
            return bytes.fromhex(clean)
        except ValueError:
            pass

    return payload.encode("latin1", errors="replace")


def generate_dos_packets(
    extracted_data: List[Dict[str, str]],
    target_ip: str,
    packet_count: int,
    output_path: str,
) -> int:
    """
    Simulación de un ataque DoS mediante tráfico UDP.
    Genera un PCAP con paquetes forjados hacia la IP objetivo.
    """
    packets = []
    default_payload = b"LAB_PAYLOAD"

    source_ips = {entry["ip_src"] for entry in extracted_data if entry.get("ip_src")}
    if not source_ips:
        raise RuntimeError("No se encontraron IPs de origen.")

    # Seleccionar una IP origen aleatoria del PCAP
    random_source = random.choice(list(source_ips))

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    attack_sources = []

    for ip in (random_source, local_ip):
        if any(src["ip"] == ip for src in attack_sources):
            continue
        if is_valid_ip(ip):
            attack_sources.append({
                "ip": ip,
                "payload": default_payload,
            })
        else:
            raise RuntimeError(f"IP inválida descartada: {ip}")

    if not attack_sources:
        raise RuntimeError("No hay IPs de origen válidas disponibles.")

    for src in attack_sources:
        for i in range(packet_count):
            pkt = (
                IP(src=src["ip"], dst=target_ip)
                / UDP(sport=12345, dport=12345)
                / Raw(load=src["payload"])
            )
            pkt.time = i * 0.0001
            packets.append(pkt)

    if not packets:
        raise RuntimeError("No se generó ningún paquete.")

    wrpcap(output_path, packets)
    return len(packets)


# ======================================================
#  Endpoints FastAPI
# ======================================================

@router.get("/op_dos", response_class=HTMLResponse, tags=["op_dos"])
async def dos_page(request: Request):
    """Renderiza la página del módulo DoS."""
    return templates.TemplateResponse("dos.html", {"request": request})


@router.post("/op_dos", tags=["op_dos"])
async def dos_execute(
    request: Request,
    pcap: UploadFile = File(...),
    destination_index: int = Query(0),
):

    if not pcap.filename or not pcap.filename.endswith(".pcap"):
        return render_form_error(
            templates,
            request,
            "dos.html",
            "Debe subir un archivo PCAP válido.",
        )

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(await pcap.read())
            input_path = tmp.name
    except Exception:
        return render_form_error(
            templates,
            request,
            "dos.html",
            "No se pudo guardar el PCAP de entrada.",
            status_code=500,
        )

    out_fd, output_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)

    try:
        destinations = extract_destinations(input_path)
        if not destinations:
            raise RuntimeError("No se encontraron IPs destino en el PCAP.")

        if destination_index >= len(destinations):
            raise RuntimeError(
                f"Índice fuera de rango. Valores válidos: 0-{len(destinations)-1}"
            )

        target_ip = destinations[destination_index]
        extracted_data = extract_udp_messages(input_path)

        generate_dos_packets(
            extracted_data,
            target_ip,
            DEFAULT_PACKET_COUNT,
            output_path,
        )

        return FileResponse(
            output_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=f"ataque_{target_ip.replace('.', '_')}.pcap",
        )

    except RuntimeError as e:
        return render_form_error(
            templates,
            request,
            "dos.html",
            str(e),
            status_code=500,
        )

    except Exception:
        return render_form_error(
            templates,
            request,
            "dos.html",
            "Error inesperado durante la generación del ataque DoS.",
            status_code=500,
        )

    finally:
        if os.path.exists(input_path):
            os.remove(input_path)

