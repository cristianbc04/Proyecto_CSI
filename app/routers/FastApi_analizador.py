#!/usr/bin/env python3
import subprocess
import tempfile

from fastapi import UploadFile, File, HTTPException, Query, APIRouter, Request
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
    if not pcap.filename or not pcap.filename.endswith(".pcap"):
        raise HTTPException( status_code=400, detail="Debe subir un archivo PCAP válido (.pcap)")
    
    # Guardar el pcap subido en un archivo temporal
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            contenido = await pcap.read()
            tmp.write(contenido)
            tmp_path = tmp.name
    except Exception:
        raise HTTPException(status_code=500, detail="No se pudo guardar el archivo PCAP temporal.")

    try:
        destinos = get_destinations(tmp_path)
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

