#!/usr/bin/env python3
import os
import socket
import tempfile
import random
from typing import List, Dict

from app.utils.render import render_form_error
from app.utils.operations_CommonAll import is_valid_ip, extract_destinations
from app.utils.operations_DenegacionServicios import extract_udp_messages
from fastapi import Form, UploadFile, File, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from scapy.all import IP, UDP, Raw, wrpcap


# ======================================================
#  Configuración / constantes
# ======================================================

DEFAULT_PACKET_COUNT = 50
# HEX_PAYLOAD_REGEX = re.compile(r"^[0-9a-fA-F]+$")

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def generate_dos_packets(
    extracted_data: List[Dict[str, str]],
    target_ip: str,
    packet_count: int,
    output_path: str,
):
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
    pcap: UploadFile = File(..., description="Archivo PCAP de entrada"),
    destination_index: int = Form(..., description="Índice de IP destino"),
    packet_count: int = Form(DEFAULT_PACKET_COUNT),
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

