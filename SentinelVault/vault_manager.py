import os
import shutil
import time
from typing import Optional, Dict, Any
from crypto_engine import EphemeralVMKManager, SentinelCryptoEngine
from network_trust import ZeroTrustNetworkValidator
from canary_guard import AntiRansomwareCanaryGuard, CANARY_FILENAMES


class SentinelVaultGuardian:
    """
    Orquestador principal de SentinelVault:
    - Gestiona el ciclo de vida del punto de montaje Desktop/SentinelVault
    - Valida continuamente el contexto de Red Segura
    - Contiene amenazas anti-ransomware y dispara el Kill Switch instantáneo
    """
    def __init__(
        self,
        vault_desktop_path: str,
        encrypted_store_path: str,
        policy: Dict[str, Any],
        org_secret: bytes = b"GLOBAL365-MASTER-SECRET-2026"
    ):
        self.vault_desktop_path = vault_desktop_path
        self.encrypted_store_path = encrypted_store_path
        self.policy = policy

        os.makedirs(self.vault_desktop_path, exist_ok=True)
        os.makedirs(self.encrypted_store_path, exist_ok=True)

        self.vmk_mgr = EphemeralVMKManager()
        self.crypto_engine = SentinelCryptoEngine(self.vmk_mgr, org_secret_key=org_secret)
        self.network_validator = ZeroTrustNetworkValidator(self.policy)

        self.canary_guard = AntiRansomwareCanaryGuard(
            vault_path=self.vault_desktop_path,
            on_threat_detected=self.handle_security_threat
        )

        self.is_unlocked = False
        self.canary_guard.deploy_canaries()

    def handle_security_threat(self, threat_type: str, details: str):
        """Respuesta síncrona en < 5 segundos ante manipulación de canaries o anomalías."""
        print(f"\n🚨 [CRÍTICO] ALERTA DE AMENAZA EN BÓVEDA: {threat_type}")
        print(f"   Detalle: {details}")
        print("   -> Ejecutando contención inmediata: Destruyendo clave VMK en RAM...")
        self.lock_and_purge_vault(reason=f"CONTENCIÓN HOSTIL: {threat_type}")

    def unlock_vault(self) -> Dict[str, Any]:
        """Intenta desbloquear la bóveda evaluando la Red Segura."""
        trust_eval = self.network_validator.evaluate_trust()
        if not trust_eval["is_network_secure"]:
            self.lock_and_purge_vault(reason=trust_eval["reason"])
            return {
                "success": False,
                "status": "LOCKED",
                "evaluation": trust_eval
            }

        self.is_unlocked = True
        return {
            "success": True,
            "status": "MOUNTED_UNLOCKED",
            "score_trust": trust_eval["score_trust"],
            "vault_path": self.vault_desktop_path
        }

    def sync_and_encrypt_document(self, local_filename: str) -> Dict[str, Any]:
        """Cifra un archivo depositado en la bóveda hacia el almacenamiento seguro subyacente."""
        if not self.is_unlocked:
            raise PermissionError("Bóveda bloqueada: No se pueden procesar archivos fuera de la red segura.")

        src_path = os.path.join(self.vault_desktop_path, local_filename)
        dest_path = os.path.join(self.encrypted_store_path, local_filename + ".sntvlt")

        # No procesar los archivos canary como documentos de usuario
        if local_filename in CANARY_FILENAMES:
            return {"status": "SKIPPED_CANARY"}

        stats = self.crypto_engine.encrypt_file(
            input_path=src_path,
            output_path=dest_path,
            user_id=101,
            device_id="WIN11-OFFICE"
        )
        return {
            "status": "ENCRYPTED_IN_STORE",
            "file": local_filename,
            "uuid": stats["file_uuid"],
            "entropy": stats["ciphertext_entropy"],
            "pii_detected": stats["privacy_audit_iso29100"]["counts"]
        }

    def lock_and_purge_vault(self, reason: str = "POLÍTICA_DE_RED") -> Dict[str, Any]:
        """
        Bloquea la bóveda y destruye la clave VMK en memoria RAM (SecureZeroMemory).
        Limpia los archivos en texto plano del escritorio para proteger la información.
        """
        self.is_unlocked = False
        kill_res = self.vmk_mgr.trigger_kill_switch()

        # Limpiar archivos en texto plano del escritorio dejando intactos los canaries y el Backing Store
        cleared_files = 0
        for item in os.listdir(self.vault_desktop_path):
            if item not in CANARY_FILENAMES:
                f_path = os.path.join(self.vault_desktop_path, item)
                try:
                    if os.path.isfile(f_path):
                        os.remove(f_path)
                        cleared_files += 1
                except Exception:
                    pass

        return {
            "status": "LOCKED_PURGED",
            "reason": reason,
            "files_cleared_from_desktop": cleared_files,
            "crypto_lease_terminated": kill_res["status"],
            "backing_store": self.encrypted_store_path
        }

    def audit_cycle(self) -> Dict[str, Any]:
        """Ciclo continuo de supervisión: valida Red Segura e integridad de Canaries."""
        canary_status = self.canary_guard.verify_canary_integrity()
        if canary_status.get("compromised"):
            return {"active": False, "reason": "CANARY_COMPROMISED"}

        trust_eval = self.network_validator.evaluate_trust()
        if not trust_eval["is_network_secure"] and self.is_unlocked:
            self.lock_and_purge_vault(reason=trust_eval["reason"])
            return {"active": False, "reason": "LOST_TRUSTED_NETWORK"}

        return {
            "active": self.is_unlocked,
            "score_trust": trust_eval["score_trust"],
            "canaries": "INTACT"
        }