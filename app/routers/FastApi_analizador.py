#!/usr/bin/env python3
import tempfile

from app.utils.render import render_form_error
from app.utils.operations_CommonAll import extract_destinations
from fastapi import UploadFile, File, APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

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
        destinos = extract_destinations(tmp_path)

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


