import os
import re
import tempfile
from dataclasses import dataclass
from typing import List

import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, ICMP

from app.utils.render import render_form_error
from fastapi import Form, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates


# ----------------------------------------
#  FastAPI setup
# ----------------------------------------
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ----------------------------------------
#  Configuración Rogue DHCP (laboratorio)
# ----------------------------------------
@dataclass(frozen=True)
class RogueConfig:
    attacker_ip: str
    attacker_mac: str
    dns_server: str
    victim_ip: str
    subnet_mask: str
    lease_time: int


ROGUE_CONFIG = RogueConfig(
    attacker_ip="172.16.0.10",
    attacker_mac="00:11:22:33:44:55",
    dns_server="suplantacion.es",
    victim_ip="172.16.0.11",
    subnet_mask="255.255.255.0",
    lease_time=3600,
)


# ----------------------------------------
#  Validaciones
# ----------------------------------------
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Valida una dirección MAC en formato XX:XX:XX:XX:XX:XX
def is_valid_mac(mac: str) -> bool:
    return bool(MAC_REGEX.fullmatch(mac))


# ----------------------------------------
#  Construcción de paquetes
# ----------------------------------------
def build_attack_packets(victim_mac: str, config: RogueConfig):
    """Genera paquetes DHCP Discover y Offer para simulación Rogue DHCP."""
    
    victim_bytes = bytes.fromhex(victim_mac.replace(":", ""))

    dhcp_discover = (
        Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=victim_bytes)
        / DHCP(options=[("message-type", "discover"), "end"])
    )

    dhcp_offer = (
        Ether(src=config.attacker_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=config.attacker_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            yiaddr=config.victim_ip,
            siaddr=config.attacker_ip,
            chaddr=victim_bytes,
        )
        / DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", config.attacker_ip),
                ("subnet_mask", config.subnet_mask),
                ("router", config.attacker_ip),
                ("domain-name-server", config.dns_server),
                ("lease_time", config.lease_time),
                "end",
            ]
        )
    )

    return dhcp_discover, dhcp_offer


def perform_dhcp_spoofing(victim_mac: str, config: RogueConfig) -> List[scapy.Packet]:
    """
    Genera tráfico DHCP + ICMP para simulación Rogue DHCP.
    """
    discover_pkt, offer_pkt = build_attack_packets(victim_mac, config)
    packets = [discover_pkt, offer_pkt]

    for _ in range(5):
        icmp_packet = (
            Ether(src=victim_mac, dst=config.attacker_mac)
            / IP(src=config.victim_ip, dst=config.attacker_ip)
            / ICMP()
        )
        packets.append(icmp_packet)

    return packets


# ----------------------------------------
#  Endpoints FastAPI
# ----------------------------------------
@router.get("/op_rogue", response_class=HTMLResponse, tags=["op_rogue"])
async def rogue_page(request: Request):
    return templates.TemplateResponse("rogue.html", {"request": request})



@router.post("/op_rogue", tags=["op_rogue"])
async def rogue_execute(
    request: Request,
    mac_victim: str = Form(..., description="MAC de la víctima")
):

    if not is_valid_mac(mac_victim):
        return render_form_error(
            templates,
            request,
            "rogue.html",
            "La dirección MAC introducida no es válida.",
            mac_victim=mac_victim,
        )

    out_fd, out_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)

    try:
        packets = perform_dhcp_spoofing(mac_victim, ROGUE_CONFIG)

        if not packets:
            raise RuntimeError("No se generaron paquetes DHCP.")

        scapy.wrpcap(out_path, packets)

        return FileResponse(
            out_path,
            media_type="application/vnd.tcpdump.pcap",
            filename="rogue.pcap",
        )

    except RuntimeError as e:
        return render_form_error(
            templates,
            request,
            "rogue.html",
            str(e),
            status_code=500,
            mac_victim=mac_victim,
        )

    except Exception:
        return render_form_error(
            templates,
            request,
            "rogue.html",
            "Se produjo un error inesperado durante la ejecución del Rogue DHCP.",
            status_code=500,
            mac_victim=mac_victim,
        )
