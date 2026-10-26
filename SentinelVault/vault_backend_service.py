import os
import time
import base64
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel

app = FastAPI(title="SentinelVault Cloud Control Plane - Global365", version="2026.1")

# Clave maestra de bóveda custodiada en la nube (en producción se lee de Google Cloud KMS)
# Corregido (32 bytes exactos):
CLOUD_MASTER_VMK = b"G365-VAULT-2026-ENCLAVE-SECRET32"

# Mock representativo de la base de datos Firestore (organizations/{org_id}/endpoints/{device_id})
FIRESTORE_DB_MOCK: Dict[str, Dict[str, Any]] = {
    "WIN11-OFFICE-8819": {
        "org_id": "ORG-VALPO-2026",
        "assigned_employee": "pcaldera@global365.cl",
        "forensic_watermark_id": 402,
        "authorized_wan_cidrs": ["152.230.234.166", "190.196.70.14"],
        "authorized_gateway_mac": "7C:7E:F9:35:6A:2D",
        "authorized_lan_prefix": "192.168.",
        "required_trust_score": 0.85,
        "kill_switch_triggered": False,
        "status": "REGISTERED"
    }
}


class LeaseRequest(BaseModel):
    device_id: str
    org_id: str
    reported_gateway_ip: str
    reported_gateway_mac: str
    firewall_active: bool
    antivirus_realtime: bool
    no_critical_ioa: bool


@app.post("/api/vault/lease")
async def issue_cryptographic_lease(payload: LeaseRequest, request: Request):
    """
    Evalúa la ecuación Zero-Trust S_trust(t) y emite un arrendamiento criptográfico
    con validez estricta de 900 segundos (Hard TTL de 15 minutos).
    """
    device_record = FIRESTORE_DB_MOCK.get(payload.device_id)
    if not device_record:
        raise HTTPException(status_code=403, detail="Dispositivo no registrado en el inventario Global365.")

    # 1. Inspeccionar IP pública real observada por el servidor
    client_wan_ip = request.client.host if request.client else "152.230.234.166"
    # Fallback si se ejecuta detrás de proxy Cloud Run
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_wan_ip = forwarded_for.split(",")[0].strip()

    # 2. Comprobar Disyuntores Críticos No Negociables B_k in {0, 1}
    b_firewall = 1 if payload.firewall_active else 0
    b_av = 1 if payload.antivirus_realtime else 0
    b_no_ioa = 1 if payload.no_critical_ioa else 0
    b_kill_switch = 0 if device_record.get("kill_switch_triggered", False) else 1

    disyuntor = b_firewall * b_av * b_no_ioa * b_kill_switch
    if disyuntor == 0:
        raise HTTPException(
            status_code=403,
            detail="ACCESO DENEGADO: Disyuntor de postura fallido o Kill Switch remoto activado."
        )

    # 3. Ponderación de Atributos Contextuales S_trust(t)
    score_wan = 1.0 if client_wan_ip in device_record["authorized_wan_cidrs"] else 0.0
    score_mac = 1.0 if payload.reported_gateway_mac == device_record["authorized_gateway_mac"] else 0.0
    score_lan = 1.0 if payload.reported_gateway_ip.startswith(device_record["authorized_lan_prefix"]) else 0.0

    # w1 = 0.40 (IP WAN), w2 = 0.40 (MAC Gateway L2), w3 = 0.20 (Subred LAN)
    s_trust = (0.40 * score_wan) + (0.40 * score_mac) + (0.20 * score_lan)
    required_score = device_record.get("required_trust_score", 0.85)

    if s_trust < required_score:
        raise HTTPException(
            status_code=403,
            detail=f"ACCESO DENEGADO: Puntuación Zero-Trust insuficiente ({s_trust:.2f} < {required_score}). Dispositivo fuera de perímetro seguro."
        )

    # 4. Generar Arrendamiento y Token de Vida (TTL: 900 segundos)
    now_utc = int(time.time())
    expires_utc = now_utc + 900  # 15 minutos

    # En producción la clave viaja cifrada hacia la clave pública del TPM 2.0
    wrapped_vmk_b64 = base64.b64encode(CLOUD_MASTER_VMK).decode("utf-8")

    device_record["status"] = "MOUNTED_UNLOCKED"
    device_record["last_lease_issued_utc"] = datetime.now(timezone.utc).isoformat()

    return {
        "status": "LEASE_GRANTED",
        "trust_score": round(s_trust, 2),
        "detected_wan_ip": client_wan_ip,
        "ttl_seconds": 900,
        "expires_timestamp_utc": expires_utc,
        "ephemeral_vmk_payload": wrapped_vmk_b64
    }


@app.post("/api/vault/admin/kill-switch")
async def trigger_admin_kill_switch(device_id: str, active: bool = True):
    """
    Endpoint administrativo disparado desde portal_admin.html para revocar
    instantáneamente el acceso a una bóveda corporativa.
    """
    if device_id not in FIRESTORE_DB_MOCK:
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado.")

    FIRESTORE_DB_MOCK[device_id]["kill_switch_triggered"] = active
    FIRESTORE_DB_MOCK[device_id]["status"] = "REVOKED_KILL_SWITCH" if active else "RESTORED"

    return {
        "device_id": device_id,
        "kill_switch_active": active,
        "timestamp_utc": datetime.now(timezone.utc).isoformat()
    }