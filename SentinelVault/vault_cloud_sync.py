import time
import base64
import threading
from typing import Dict, Any, Optional
from network_trust import get_public_wan_ip, get_default_gateway_ip, get_gateway_mac_address
from crypto_engine import EphemeralVMKManager
from vault_manager import SentinelVaultGuardian


class CloudLeaseClient:
    """
    Cliente de sincronización de políticas y claves criptográficas entre el
    endpoint local y el backend de Global365 en Google Cloud Run.
    """
    def __init__(
        self,
        guardian: SentinelVaultGuardian,
        device_id: str = "WIN11-OFFICE-8819",
        org_id: str = "ORG-VALPO-2026",
        backend_mock_app=None
    ):
        self.guardian = guardian
        self.device_id = device_id
        self.org_id = org_id
        self.backend = backend_mock_app
        self.lease_active = False
        self.lease_expires_utc = 0
        self.listener_running = False

    def request_new_lease(self) -> Dict[str, Any]:
        """Envía telemetría y solicita la VMK efímera sujeta a TTL."""
        gw_ip = get_default_gateway_ip()
        gw_mac = get_gateway_mac_address(gw_ip)

        payload = {
            "device_id": self.device_id,
            "org_id": self.org_id,
            "reported_gateway_ip": gw_ip,
            "reported_gateway_mac": gw_mac,
            "firewall_active": True,
            "antivirus_realtime": True,
            "no_critical_ioa": True
        }

        # Simulación de llamada síncrona al backend FastAPI
        from vault_backend_service import FIRESTORE_DB_MOCK, CLOUD_MASTER_VMK

        rec = FIRESTORE_DB_MOCK.get(self.device_id)
        if not rec or rec.get("kill_switch_triggered"):
            self.guardian.lock_and_purge_vault(reason="KILL_SWITCH_ACTIVO_EN_FIRESTORE")
            return {"success": False, "error": "KILL_SWITCH_ACTIVO"}

        # Validar contexto de red
        if gw_mac != rec["authorized_gateway_mac"]:
            self.guardian.lock_and_purge_vault(reason="GATEWAY_MAC_NO_AUTORIZADA")
            return {"success": False, "error": "UNTRUSTED_NETWORK"}

        # Desbloquear y cargar VMK en la RAM local
        raw_vmk = CLOUD_MASTER_VMK
        self.guardian.vmk_mgr = EphemeralVMKManager(raw_vmk)
        self.guardian.crypto_engine.vmk_manager = self.guardian.vmk_mgr
        self.guardian.is_unlocked = True

        self.lease_expires_utc = int(time.time()) + 900
        self.lease_active = True

        return {
            "success": True,
            "status": "MOUNTED_UNLOCKED",
            "trust_score": 1.0,
            "ttl_seconds": 900,
            "expires_timestamp": self.lease_expires_utc
        }

    def start_realtime_firestore_listener(self):
        """
        Simula el canal on_snapshot/gRPC de Firestore (< 1.5s de respuesta).
        Si el campo kill_switch_triggered cambia a True, purga la bóveda al instante.
        """
        self.listener_running = True

        def _listener_loop():
            from vault_backend_service import FIRESTORE_DB_MOCK
            while self.listener_running:
                rec = FIRESTORE_DB_MOCK.get(self.device_id, {})
                if rec.get("kill_switch_triggered") and self.guardian.is_unlocked:
                    print("\n⚡ [FIRESTORE PUSH] ORDEN DE REVOCACIÓN INMEDIATA RECIBIDA (< 1.5s)")
                    self.guardian.lock_and_purge_vault(reason="ADMIN_KILL_SWITCH_CLOUD_REVOCATION")
                    self.lease_active = False
                time.sleep(0.5)

        thread = threading.Thread(target=_listener_loop, daemon=True)
        thread.start()

    def stop_listener(self):
        self.listener_running = False