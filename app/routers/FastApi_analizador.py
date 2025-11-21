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

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def obtener_destinos(pcap_file):
    TSHARK_COMMAND = [ # comandos para poder analizar el archivo .pcacp que se le pase.
        "tshark",
        "-r", pcap_file, # para saber que archivo es el que vamos a leer.
        "-T", "fields", 
        "-e", "ip.dst", # sirve para poder extraer el campo IP 
        "udp" # filtra los paquetes por UDP 
    ]
    
    try:
        resultado = subprocess.run(TSHARK_COMMAND, capture_output=True, text=True, check=True)
        lineas = resultado.stdout.strip().split('\n')
        destinos = set([linea.strip() for linea in lineas if linea.strip()])
        return destinos

    except subprocess.CalledProcessError as e: # esto de aqui es lo que devuelve check si es false, 'e' tendra el error.
        print(f"[ERROR] No se pudo ejecutar tshark: {e}")
        return set()
    
@router.get("/op_analizador", response_class=HTMLResponse, tags=["op_analizador"])
async def cargar_pagina_html(request: Request):
    return templates.TemplateResponse("analizador.html", {"request": request})

@router.post("/op_analizador", tags=["op_analizador"])
async def analizador_paquete(
    request: Request,
    pcap: UploadFile = File(..., description="Archivo PCAP de entrada")
):
    """Recibe un pcap, devuelve el numero de paquetes distintos de destino"""
    # Guardar el pcap subido en un archivo temporal
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            contenido = await pcap.read()
            tmp.write(contenido)
            tmp_path = tmp.name
    except Exception:
        raise HTTPException(status_code=500, detail="No se pudo guardar el archivo PCAP temporal.")

    try:
        destinos = obtener_destinos(tmp_path)
    except Exception as e:
        # Cualquier error en tshark o análisis
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Limpieza del archivo temporal
        try:
            import os
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

    # devuelto en formato json a la vista que trata con el parametro pasado en context
    return templates.TemplateResponse( 
        name="valores_json.html", 
        context={
            "request": request, # requerido por el paremetro context           
            "total_destinos": len(destinos),
            "destinos": list(destinos)
        })

