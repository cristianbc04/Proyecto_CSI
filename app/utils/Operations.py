import ipaddress
import subprocess
from typing import List


def is_valid_ip(address: str) -> bool:
    """Comprueba si una IP es válida."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def extract_destinations(pcap_path: str) -> List[str]:
    """
    Extrae IPs destino únicas de tráfico UDP usando tshark.
    Mantiene el orden de aparición.
    """
    
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.dst",
        "udp",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error ejecutando tshark: {e}") from e

    destinations: List[str] = []
    seen = set()

    for line in result.stdout.splitlines():
        ip = line.strip()
        if ip and ip not in seen:
            seen.add(ip)
            destinations.append(ip)

    return destinations