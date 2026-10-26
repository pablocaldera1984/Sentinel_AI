import struct
import zlib
from typing import Optional

# Caracteres Unicode de Ancho Cero (Zero-Width Characters)
ZWC_ZERO = "\u200B"   # Zero Width Space (UTF-8: e2 80 8b) -> Bit 0
ZWC_ONE = "\u200C"    # Zero Width Non-Joiner (UTF-8: e2 80 8c) -> Bit 1
ZWC_FRAME = "\u200D"  # Zero Width Joiner -> Delimitador de trama


def _crc16(data: bytes) -> int:
    """Calcula un checksum CRC-16 sobre los 6 bytes de metadatos forenses."""
    return zlib.crc32(data) & 0xFFFF


def strip_existing_zwc(text: str) -> str:
    """Purga cualquier marca esteganográfica previa para evitar colisiones."""
    for ch in (ZWC_ZERO, ZWC_ONE, ZWC_FRAME):
        text = text.replace(ch, "")
    return text


def build_zwc_watermark(user_id: int, device_id: int, timestamp_hours: int) -> str:
    """
    Codifica un identificador forense de 64 bits (8 bytes) en caracteres invisibles:
    - user_id (16 bits: 0 - 65535)
    - device_id (16 bits: 0 - 65535)
    - timestamp_hours (16 bits)
    - crc16 (16 bits: verificador criptográfico de integridad)
    """
    payload_6bytes = struct.pack(
        ">HHH",
        user_id & 0xFFFF,
        device_id & 0xFFFF,
        timestamp_hours & 0xFFFF
    )
    checksum = _crc16(payload_6bytes)
    full_8bytes = payload_6bytes + struct.pack(">H", checksum)

    bits_str = "".join(f"{byte:08b}" for byte in full_8bytes)
    encoded_zwc = "".join(ZWC_ONE if b == "1" else ZWC_ZERO for b in bits_str)
    return f"{ZWC_FRAME}{encoded_zwc}{ZWC_FRAME}"


def embed_forensic_mark(text: str, user_id: int, device_id: int, timestamp_hours: int) -> str:
    """Limpia metadatos ZWC previos e inyecta la huella forense invisible tras el primer espacio."""
    clean_text = strip_existing_zwc(text)
    watermark = build_zwc_watermark(user_id, device_id, timestamp_hours)
    if " " in clean_text:
        idx = clean_text.index(" ")
        return clean_text[:idx + 1] + watermark + clean_text[idx + 1:]
    return watermark + clean_text


def decode_forensic_mark(leaked_text: str) -> Optional[dict]:
    """
    Extrae y valida criptográficamente la identidad de origen (Usuario y Equipo)
    a partir de un fragmento de texto filtrado en correos, chats o web.
    """
    parts = leaked_text.split(ZWC_FRAME)
    if len(parts) < 3:
        return None

    zwc_candidate = parts[1]
    bits = [
        "1" if ch == ZWC_ONE else "0"
        for ch in zwc_candidate
        if ch in (ZWC_ZERO, ZWC_ONE)
    ]

    if len(bits) != 64:
        return None

    bit_string = "".join(bits)
    raw_bytes = int(bit_string, 2).to_bytes(8, byteorder="big")

    user_id, device_id, timestamp_hours, extracted_crc = struct.unpack(">HHHH", raw_bytes)
    expected_crc = _crc16(raw_bytes[:6])

    if extracted_crc != expected_crc:
        return None

    return {
        "verified": True,
        "user_id": user_id,
        "device_id": device_id,
        "timestamp_hours": timestamp_hours,
        "integrity_crc16": hex(extracted_crc)
    }