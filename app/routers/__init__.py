from .FastApi_ddos import router as ddos_router
from .FastApi_analizador import router as analizador_router
from .FastApi_portscan import router as portscan_router
from .FastApi_dos import router as dos_router
from .FastApi_arpSpoofing import router as arp_router
from .FastApi_rogue import router as rogue_router

__all__ = [
    "ddos_router",
    "analizador_router",
    "portscan_router",
    "dos_router",
    "arp_router",
    "rogue_router",
]
