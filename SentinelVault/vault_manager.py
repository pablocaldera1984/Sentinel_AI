# -*- coding: utf-8 -*-
import os
import sys
import shutil
import time
import base64
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from crypto_engine import EphemeralVMKManager, SentinelCryptoEngine
from network_trust import ZeroTrustNetworkValidator
from canary_guard import AntiRansomwareCanaryGuard, CANARY_FILENAMES
from privacy_compliance import DeepDiskPIIRemediator, generate_blind_index


class SentinelVaultGuardian:
    """
    Orquestador principal de SentinelVault:
    - Gestiona el ciclo de vida del punto de montaje Desktop/SentinelVault
    - Valida continuamente el contexto de Red Segura
    - Contiene amenazas anti-ransomware y dispara el Kill Switch instantáneo
    - Ejecuta Rastreo Profundo Multi-Formato y Supresión Quirúrgica en todo el PC (Ley 21.719)
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
        self.org_secret = org_secret

        os.makedirs(self.vault_desktop_path, exist_ok=True)
        os.makedirs(self.encrypted_store_path, exist_ok=True)

        self.vmk_mgr = EphemeralVMKManager()
        self.crypto_engine = SentinelCryptoEngine(self.vmk_mgr, org_secret_key=org_secret)
        self.network_validator = ZeroTrustNetworkValidator(self.policy)
        self.disk_remediator = DeepDiskPIIRemediator(org_secret_key=org_secret)

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
            "pii_detected": stats["privacy_audit_iso29100"]["counts"],
            "privacy_audit_full": stats["privacy_audit_iso29100"]
        }

    def lock_and_purge_vault(self, reason: str = "POLÍTICA_DE_RED", lock_os_user: Optional[str] = None) -> Dict[str, Any]:
        """
        Bloquea la bóveda y destruye la clave VMK en memoria RAM (SecureZeroMemory).
        Limpia los archivos en texto plano del escritorio para proteger la información.
        Si se especifica lock_os_user (Offboarding Art. 14 bis), bloquea la sesión Windows y deshabilita la cuenta.
        """
        self.is_unlocked = False
        kill_res = self.vmk_mgr.trigger_kill_switch()

        # Limpiar archivos en texto plano del escritorio dejando intactos los canaries y el Backing Store
        cleared_files = 0
        if os.path.exists(self.vault_desktop_path):
            for item in os.listdir(self.vault_desktop_path):
                if item not in CANARY_FILENAMES:
                    f_path = os.path.join(self.vault_desktop_path, item)
                    try:
                        if os.path.isfile(f_path):
                            os.remove(f_path)
                            cleared_files += 1
                    except Exception:
                        pass

        os_lock_status = "NOT_REQUESTED"
        if lock_os_user and sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            try:
                subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], capture_output=True, creationflags=creation_flags)
                if str(lock_os_user).strip().upper() not in ("", "TODOS", "ALL", "SYSTEM"):
                    r_net = subprocess.run(
                        ["net", "user", str(lock_os_user).strip(), "/active:no"],
                        capture_output=True, text=True, creationflags=creation_flags
                    )
                    os_lock_status = "USER_DISABLED_AND_SCREEN_LOCKED" if r_net.returncode == 0 else "SCREEN_LOCKED_ONLY"
                else:
                    os_lock_status = "SCREEN_LOCKED_ONLY"
            except Exception as e_os:
                os_lock_status = f"OS_LOCK_ERROR: {e_os}"

        return {
            "status": "LOCKED_PURGED",
            "reason": reason,
            "files_cleared_from_desktop": cleared_files,
            "crypto_lease_terminated": kill_res["status"],
            "os_account_action": os_lock_status,
            "backing_store": self.encrypted_store_path,
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
        }

    def scan_entire_pc_for_subject(self, queries: List[str]) -> Dict[str, Any]:
        """
        Busca un RUT y/o Nombre en todas las carpetas del PC (Desktop, Documents, Downloads, OneDrive y Bóveda),
        inspeccionando el interior de archivos .xlsx, .docx, .pdf, .csv, .txt, .json y cabeceras .sntvlt.
        """
        extra = [self.vault_desktop_path]
        report = self.disk_remediator.search_across_pc(target_queries=queries, extra_roots=extra)

        # Inspeccionar también las cabeceras de 4 KB de los contenedores cifrados .sntvlt
        target_blind_hashes = {generate_blind_index(q, self.org_secret) for q in queries if q}
        encrypted_matches = []
        if os.path.exists(self.encrypted_store_path):
            for fname in os.listdir(self.encrypted_store_path):
                if fname.endswith(".sntvlt"):
                    fpath = os.path.join(self.encrypted_store_path, fname)
                    try:
                        hdr = self.crypto_engine.inspect_header_only(fpath)
                        b_list = hdr.get("metadata", {}).get("b_idx", [])
                        if any(bh in b_list for bh in target_blind_hashes) or any(
                            q.lower().replace(" ", "") in fname.lower().replace("_", "") for q in queries if q
                        ):
                            encrypted_matches.append({
                                "file_name": fname,
                                "full_path": fpath,
                                "extension": ".sntvlt",
                                "occurrences": 1,
                                "snippets": ["[Coincidencia en Cabecera Criptográfica Blind Index SHA-256]"],
                                "sensitivity": hdr.get("metadata", {}).get("sens", "C"),
                                "categories": ["ENCRYPTED_VAULT_CONTAINER"],
                                "total_ruts_in_file": hdr.get("metadata", {}).get("ruts", 1),
                                "size_bytes": os.path.getsize(fpath)
                            })
                    except Exception:
                        pass

        report["matches"].extend(encrypted_matches)
        report["total_files_matched"] = len(report["matches"])
        report["blind_indexes_queried"] = list(target_blind_hashes)
        return report

    def surgical_delete_subject_across_pc(
        self,
        queries: List[str],
        acta_id: str = "ARSOP-21719",
        target_paths: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Recorre todos los archivos del PC donde aparece el titular (o las rutas indicadas),
        sobreescribe exclusivamente su RUT y/o Nombre sin dañar los registros de otras personas,
        y empaqueta los archivos sanitizados (hasta 5 MB en Base64) para descarga de evidencia en portal_admin.html.
        """
        if not target_paths:
            scan_res = self.scan_entire_pc_for_subject(queries)
            target_paths = [m["full_path"] for m in scan_res.get("matches", [])]

        intervened_files = []
        total_redactions = 0

        for fpath in target_paths:
            if not os.path.exists(fpath):
                continue

            # Si es un archivo dentro de la bóveda que también tiene respaldo .sntvlt, actualizar el .sntvlt después
            if fpath.endswith(".sntvlt"):
                # Verificar si existe el archivo abierto en vault_desktop_path; si no, descifrar temporalmente para edición quirúrgica
                orig_name = os.path.basename(fpath)[:-7]
                temp_plain = os.path.join(self.vault_desktop_path, orig_name)
                estaba_en_escritorio = os.path.exists(temp_plain)
                try:
                    if not estaba_en_escritorio and self.is_unlocked:
                        self.crypto_engine.decrypt_file(fpath, temp_plain)
                    if os.path.exists(temp_plain):
                        res_red = self.disk_remediator.surgical_redact_file(temp_plain, queries, acta_id=acta_id)
                        if res_red.get("success") and res_red.get("redacted_instances", 0) > 0:
                            self.sync_and_encrypt_document(orig_name)
                            total_redactions += res_red.get("redacted_instances", 0)
                            # Empaquetar copia sanitizada para descarga del titular
                            b64_data = None
                            if os.path.getsize(temp_plain) <= 5 * 1024 * 1024:
                                with open(temp_plain, "rb") as fb:
                                    b64_data = base64.b64encode(fb.read()).decode("utf-8")
                            res_red["sanitized_file_b64"] = b64_data
                            intervened_files.append(res_red)
                        if not estaba_en_escritorio and os.path.exists(temp_plain):
                            os.remove(temp_plain)
                        continue
                except Exception:
                    pass

            # Archivo estándar en cualquier carpeta del PC (.xlsx, .docx, .pdf, .csv, .txt)
            res = self.disk_remediator.surgical_redact_file(fpath, queries, acta_id=acta_id)
            if res.get("success") and res.get("redacted_instances", 0) > 0:
                total_redactions += res.get("redacted_instances", 0)
                b64_data = None
                try:
                    if os.path.getsize(fpath) <= 5 * 1024 * 1024:
                        with open(fpath, "rb") as fb:
                            b64_data = base64.b64encode(fb.read()).decode("utf-8")
                except Exception:
                    pass
                res["sanitized_file_b64"] = b64_data
                intervened_files.append(res)

                # Si ese archivo estaba dentro de la carpeta bóveda, re-sincronizar su .sntvlt
                if os.path.dirname(os.path.normpath(fpath)) == os.path.normpath(self.vault_desktop_path):
                    try:
                        self.sync_and_encrypt_document(os.path.basename(fpath))
                    except Exception:
                        pass

        return {
            "acta_id": acta_id,
            "queries_suppressed": queries,
            "files_intervened_count": len(intervened_files),
            "total_instances_overwritten": total_redactions,
            "intervened_files": intervened_files,
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
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