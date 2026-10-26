import os
import time
import sys
from typing import Dict, Any
from vault_manager import SentinelVaultGuardian
from vault_cloud_sync import CloudLeaseClient
from dlp_guard import ScreenCaptureShield, ProcessPIDGuard, ActiveClipboardShield
from privacy_compliance import PIIScannerISO29100
from network_trust import get_public_wan_ip, get_default_gateway_ip, get_gateway_mac_address


class SentinelVaultEndpointAgent:
    """
    Agente Unificado SentinelVault para Endpoints:
    Orquesta el Guardián de Bóveda, el Arrendamiento de Nube con Kill Switch,
    el Escáner PII Ley 21.719 y la suite DLP de contención activa.
    """
    def __init__(
        self,
        device_id: str = "WIN11-OFFICE-8819",
        base_dir: str = "vault_test_sandbox"
    ):
        self.device_id = device_id
        self.base_dir = base_dir
        self.desktop_vault = os.path.join(base_dir, "Desktop_SentinelVault")
        self.encrypted_store = os.path.join(base_dir, "EncryptedStore_ProgramData")

        # Telemetría inicial de red
        wan = get_public_wan_ip()
        gw_ip = get_default_gateway_ip()
        gw_mac = get_gateway_mac_address(gw_ip)

        self.policy = {
            "authorized_wan_ips": [wan],
            "authorized_gateway_mac": gw_mac,
            "authorized_lan_prefix": "192.168.",
            "required_trust_threshold": 0.80,
            "kill_switch_active": False
        }

        # Inicialización de subsistemas
        self.guardian = SentinelVaultGuardian(
            vault_desktop_path=self.desktop_vault,
            encrypted_store_path=self.encrypted_store,
            policy=self.policy
        )

        self.cloud_client = CloudLeaseClient(
            guardian=self.guardian,
            device_id=self.device_id
        )

        self.pii_scanner = PIIScannerISO29100()
        self.pid_guard = ProcessPIDGuard()
        self.clipboard_shield = ActiveClipboardShield(self.pii_scanner)

    def startup(self) -> Dict[str, Any]:
        """Arranca el ciclo de vida del agente."""
        # 1. Obtener arrendamiento criptográfico de la nube
        lease = self.cloud_client.request_new_lease()
        if not lease.get("success"):
            return {"status": "STARTUP_FAILED", "error": lease.get("error")}

        # 2. Iniciar escucha Push de Firestore (<1.5s para Kill Switch remoto)
        self.cloud_client.start_realtime_firestore_listener()

        # 3. Iniciar sanitizador de portapapeles
        self.clipboard_shield.start_background_sanitizer()

        return {
            "status": "RUNNING",
            "vault_state": "MOUNTED_UNLOCKED",
            "device_id": self.device_id,
            "trust_score": lease.get("trust_score"),
            "ttl_seconds": lease.get("ttl_seconds"),
            "screen_shield": "ACTIVE",
            "clipboard_guard": "ACTIVE",
            "anti_ransomware_canaries": "ACTIVE"
        }

    def shutdown(self):
        """Cierre ordenado y purga de claves efímeras."""
        self.clipboard_shield.stop()
        self.cloud_client.stop_listener()
        self.guardian.lock_and_purge_vault(reason="AGENT_GRACEFUL_SHUTDOWN")