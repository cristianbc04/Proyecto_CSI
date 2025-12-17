#!/usr/bin/env python3
import os
import tempfile
from typing import List, Dict

from app.utils.render import render_form_error
from app.utils.operations_CommonAll import is_valid_ip, extract_destinations
from app.utils.operations_DenegacionServicios import extract_udp_messages, payload_to_bytes
from fastapi import Form, UploadFile, File, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from scapy.all import IP, UDP, Raw, wrpcap


# ======================================================
#  Configuración y constantes
# ======================================================

DEFAULT_PACKET_COUNT = 50
# HEX_PAYLOAD_REGEX = re.compile(r"^[0-9a-fA-F]+$")

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ======================================================
#  Generación de tráfico "de ataque"
# ======================================================

def generate_attack_pcap(
    extracted_data: List[Dict[str, str]],
    target_ip: str,
    packet_count: int,
    output_path: str,
):
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
        if src not in payload_by_src and entry.get("payload"):
            payload_by_src[src] = entry["payload"]

    for src_ip in source_ips:
        payload_hex = next(
            (
                d["payload"]
                for d in extracted_data
                if d["ip_src"] == src_ip and d["ip_dst"] == target_ip
            ),
            payload_by_src.get(src_ip),
        )

        payload_bytes = (
            payload_to_bytes(payload_hex)
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


# ======================================================
#  Endpoints FastAPI
# ======================================================

@router.get("/op_ddos", response_class=HTMLResponse, tags=["op_ddos"])
async def ddos_page(request: Request):
    return templates.TemplateResponse("ddos.html", {"request": request})


@router.post("/op_ddos", response_class=FileResponse, tags=["op_ddos"])
async def ddos_execute(
    request: Request,
    pcap: UploadFile = File(..., description="Archivo PCAP de entrada"),
    destination_index: int = Form(..., description="Índice de IP destino"),
    packet_count: int = Form(DEFAULT_PACKET_COUNT),
):
    # Guardar PCAP de entrada
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(await pcap.read())
            input_path = tmp.name
    except Exception:
        return render_form_error(
            templates,
            request,
            "ddos.html",
            "No se pudo guardar el PCAP de entrada.",
            status_code=500,
        )

    # Archivo de salida
    out_fd, output_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)

    try:
        destinations = extract_destinations(input_path)
        if not destinations:
            raise RuntimeError("No se encontraron IP destino en el PCAP")

        if destination_index >= len(destinations):
            raise RuntimeError(
                f"Índice fuera de rango. Valores válidos: 0-{len(destinations)-1}"
            )

        target_ip = destinations[destination_index]
        extracted_data = extract_udp_messages(input_path)

        # 🔹 FILTRADO CLAVE POR DESTINO
        filtered_data = [
            entry for entry in extracted_data
            if entry["ip_dst"] == target_ip
        ]

        if not filtered_data:
            raise RuntimeError(
                f"No hay tráfico UDP hacia la IP destino seleccionada: {target_ip}"
            )

        generate_attack_pcap(
            filtered_data,
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
        return render_form_error(
            templates,
            request,
            "ddos.html",
            str(e),
            status_code=500,
        )
    
    except Exception:
        return render_form_error(
            templates,
            request,
            "ddos.html",
            "Error inesperado durante la generación del ataque DDoS.",
            status_code=500,
        )

    finally:
        if os.path.exists(input_path):
            os.remove(input_path)
