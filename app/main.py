from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.routers.FastApi_ddos import router as ddos_router
from app.routers.FastApi_analizador import router as analizador
from app.routers.FastApi_portscan import router as portscan
from app.routers.FastApi_dos import router as dos

app = FastAPI(title="Mi API CSI")

# static y templates (ojo con las rutas)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

app.include_router(ddos_router)
app.include_router(analizador)
app.include_router(portscan)
app.include_router(dos)

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
