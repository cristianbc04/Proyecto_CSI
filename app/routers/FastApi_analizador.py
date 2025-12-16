#!/usr/bin/env python3
import subprocess
import tempfile

from app.utils.render import render_form_error
from fastapi import UploadFile, File, APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# ----------------------------------------
#  Funciones internas
# ----------------------------------------
def get_destinations(pcap_file):
    """ Funcion que obtiene cantidad de destinos del pcap """
    
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

    except subprocess.CalledProcessError as e:
        raise RuntimeError("Error ejecutando tshark") from e  

# ----------------------------------------
#  Endpoints FastAPI
# ----------------------------------------
@router.get("/op_analizador", response_class=HTMLResponse, tags=["op_analizador"])
async def analizador_page(request: Request):
    return templates.TemplateResponse("analizador.html", {"request": request})


@router.post("/op_analizador", tags=["op_analizador"])
async def analizador_execute(
    request: Request,
    pcap: UploadFile = File(..., description="Archivo PCAP de entrada")
):

    if not pcap.filename:
        return render_form_error(
            templates,
            request,
            "analizador.html",
            "No se ha seleccionado ningún archivo."
        )

    if not pcap.filename.endswith(".pcap"):
        return render_form_error(
            templates,
            request,
            "analizador.html",
            "Debe subir un archivo Pcap"
        )

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            contenido = await pcap.read()
            tmp.write(contenido)
            tmp_path = tmp.name
    except Exception:
        return render_form_error(
            templates,
            request,
            "analizador.html",
            "No se pudo guardar el archivo PCAP temporal.",
            status_code=500,
        )

    try:
        destinos = get_destinations(tmp_path)

    except RuntimeError as e:
        return render_form_error(
            templates,
            request,
            "analizador.html",
            str(e),
            status_code=500,
        )

    except Exception:
        return render_form_error(
            templates,
            request,
            "analizador.html",
            "Error inesperado durante el análisis del tráfico.",
            status_code=500,
        )

    finally:
        try:
            import os
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

    return templates.TemplateResponse(
        "salida_jsonAnalizador.html",
        {
            "request": request,
            "total_destinos": len(destinos),
            "destinos": list(destinos),
        },
    )


