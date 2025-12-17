import re
import subprocess
from typing import Dict, List

HEX_PAYLOAD_REGEX = re.compile(r"^[0-9a-fA-F]+$")

def parse_message_lines(lines: List[str]) -> List[Dict[str, str]]:
    """
    Procesa líneas de tshark con formato:
    ip.src \\t ip.dst \\t data.data
    """
    parsed = []

    for line in lines:
        fields = line.strip().split("\t")
        if len(fields) < 3:
            continue

        src_ip, dst_ip, payload = map(str.strip, fields[:3])
        if not (src_ip and dst_ip and payload):
            continue

        parsed.append({
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "payload": payload,
        })

    return parsed

def extract_udp_messages(pcap_path: str) -> List[Dict[str, str]]:
    """Extrae mensajes UDP (payload) desde un PCAP usando tshark."""
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "data.data",
        "udp",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"No se pudieron extraer mensajes UDP: {e}") from e

    return parse_message_lines(result.stdout.splitlines())


def payload_to_bytes(payload: str) -> bytes:
    """
    Convierte un payload en formato string a bytes.
    Si es hexadecimal válido, se decodifica; si no, se trata como texto.
    """
    clean = payload.replace(":", "").replace(" ", "")

    if HEX_PAYLOAD_REGEX.fullmatch(clean) and len(clean) % 2 == 0:
        try:
            return bytes.fromhex(clean)
        except ValueError:
            pass

    return payload.encode("latin1", errors="replace")