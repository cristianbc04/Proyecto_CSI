#!/usr/bin/env python3
import pyfiglet
import socket
from datetime import datetime
from contextlib import closing

from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# ----------------------------------------
#  Funciones internas
# ----------------------------------------
def banner(target: str) -> str:
    """ Obtencio de banner para vista del json """
    
    ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
    lines = [
        ascii_banner,
        "-" * 50,
        f"Scanning Target: {target}",
        f"Scanning started at: {datetime.now()}",
        "-" * 50,
    ]
    return "\n".join(lines)

def PortScan(host: str, ports: str) -> str:
    """ Funcion que obtiene lista de puertos abiertos """
    
    output = []
    timeout = 0.8
    
    ports = ports.strip()
    
    # si no se le pasa puertos, se añaden todos los existentes
    if not ports:
        port_list = range(1, 65536)
    else:
        parsed_ports = set()

        for part in ports.split(","):
            part = part.strip()

            if "-" in part: # Rango de puertos (ej: 8000-8100)
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                parsed_ports.update(range(start, end + 1))
            else:
                parsed_ports.add(int(part))

        port_list = sorted(parsed_ports)
        
    # Escaneo de puertos TCP
    for port in port_list:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s: # Socket TCP auxiliar para comprobar si el puerto está abierto
            s.settimeout(timeout)
            result = s.connect_ex((host, port))

            if result == 0:
                output.append(f"[+] Port {port} OPEN")
            else:
                output.append(f"[-] Port {port} CLOSED")

    return "\n".join(output)


# ----------------------------------------
#  Endpoints FastAPI
# ----------------------------------------
@router.get("/op_portscan", response_class=HTMLResponse, tags=["op_portscan"])
async def portScan_page(request: Request):
    return templates.TemplateResponse("portscan.html", {"request": request})

@router.post("/op_portscan", response_class=HTMLResponse, tags=["op_portscan"])
async def portScan_execute(
    request: Request,
    ports: str = Form(""),
    host: str = Form(...)
):
    if not host:
        raise HTTPException(status_code=400, detail="No pasaste un host")
    
    # Texto que guarda lo que se devolvera en formato json de puertos abiertos del equipo pasado
    result_text = (
        banner(host) +
        "\n" +
        PortScan(host, ports)
    )

    return templates.TemplateResponse(
        "salida_portScan.html",
        {
            "request": request,
            "result": result_text
        }
    )
        