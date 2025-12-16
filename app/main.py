from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.routers import (
    ddos_router,
    analizador_router,
    portscan_router,
    dos_router,
    arp_router,
    rogue_router,
)

app = FastAPI(title="Mi API CSI")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

app.include_router(ddos_router)
app.include_router(analizador_router)
app.include_router(portscan_router)
app.include_router(dos_router)
app.include_router(arp_router)
app.include_router(rogue_router)

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})