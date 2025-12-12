#!/usr/bin/env python3
from typing import List
import pyfiglet
import socket
import subprocess
from datetime import datetime
from contextlib import closing
import tempfile

from fastapi import APIRouter, Request, UploadFile, File, HTTPException, Query, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# --------------------------
#   FUNCIONES INTERNAS
# --------------------------

def banner(target: str) -> str:
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
    output = []
    timeout = 0.8
    
    ports = ports.strip()

    if not ports:
        port_list = range(1, 65536)
    else:
        parsed_ports = set()

        for part in ports.split(","):
            part = part.strip()

            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                parsed_ports.update(range(start, end + 1))
            else:
                parsed_ports.add(int(part))

        port_list = sorted(parsed_ports)

    for port in port_list:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))

            if result == 0:
                output.append(f"[+] Port {port} OPEN")
            else:
                output.append(f"[-] Port {port} CLOSED")

    return "\n".join(output)


# --------------------------
#   RUTA HTML (GET)
# --------------------------
@router.get("/op_portscan", response_class=HTMLResponse, tags=["op_portscan"])
async def cargar_pagina_portscan(request: Request):
    return templates.TemplateResponse("portscan.html", {"request": request})


# --------------------------
#   RUTA POST (API)
# --------------------------
@router.post("/op_portscan", response_class=HTMLResponse, tags=["op_portscan"])
async def ejecutar_portscan(
    request: Request,
    ports: str = Form(""),
    host: str = Form(...)
):
    if not host:
        raise HTTPException(status_code=400, detail="Host no válido")

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
        