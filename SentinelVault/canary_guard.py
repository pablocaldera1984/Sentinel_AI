import os
import time
from typing import List, Dict, Any, Callable, Optional
from crypto_engine import calculate_shannon_entropy

CANARY_FILENAMES = [
    "!00_Claves_Tesoreria_2026.xlsx",
    "~$Presupuesto_Confidencial.docx",
    "zz_Contratos_Directorio_Backup.pdf"
]

CANARY_CONTENT = b"GLOBAL365_CANARY_INTEGRITY_TOKEN_DO_NOT_MODIFY_0x99AABBCCDDEEFF"


class AntiRansomwareCanaryGuard:
    """
    Siembra y vigila archivos trampa (Honeydocs) y evalúa el diferencial de
    Entropía de Shannon (Delta H > 3.0) para frenar ataques de cifrado hostil.
    """
    def __init__(self, vault_path: str, on_threat_detected: Optional[Callable[[str, str], None]] = None):
        self.vault_path = vault_path
        self.on_threat_detected = on_threat_detected
        self.canary_paths: List[str] = []
        self.canary_baselines: Dict[str, Dict[str, Any]] = {}

    def deploy_canaries(self):
        """Siembra los archivos trampa en ubicaciones estratégicas de la bóveda."""
        os.makedirs(self.vault_path, exist_ok=True)
        for fname in CANARY_FILENAMES:
            c_path = os.path.join(self.vault_path, fname)
            with open(c_path, "wb") as f:
                f.write(CANARY_CONTENT)
            self.canary_paths.append(c_path)
            self.canary_baselines[c_path] = {
                "size": len(CANARY_CONTENT),
                "entropy": calculate_shannon_entropy(CANARY_CONTENT),
                "mtime": os.path.getmtime(c_path)
            }

    def verify_canary_integrity(self) -> Dict[str, Any]:
        """
        Inspecciona el estado de los señuelos. Cualquier intento de eliminación,
        renombrado o alteración del contenido dispara una alerta crítica inmediata.
        """
        for c_path in self.canary_paths:
            if not os.path.exists(c_path):
                msg = f"Canary eliminado o renombrado: {os.path.basename(c_path)}"
                self._trigger_threat_containment("CANARY_TAMPER_DELETION", msg)
                return {"compromised": True, "vector": "DELETION", "file": c_path}

            current_size = os.path.getsize(c_path)
            with open(c_path, "rb") as f:
                current_bytes = f.read()

            if current_bytes != CANARY_CONTENT:
                current_entropy = calculate_shannon_entropy(current_bytes)
                delta_h = current_entropy - self.canary_baselines[c_path]["entropy"]
                msg = f"Canary modificado: {os.path.basename(c_path)} (Delta H: +{delta_h:.2f} bits/byte)"
                self._trigger_threat_containment("CANARY_TAMPER_MODIFICATION", msg)
                return {
                    "compromised": True,
                    "vector": "MODIFICATION",
                    "file": c_path,
                    "delta_entropy": delta_h
                }

        return {"compromised": False, "status": "ALL_CANARIES_INTACT"}

    def inspect_file_write_entropy(self, file_path: str, previous_bytes: bytes, incoming_bytes: bytes) -> Dict[str, Any]:
        """
        Evalúa en tiempo real si la escritura sobre un archivo legítimo corresponde
        a un proceso de cifrado masivo o intermitente de ransomware.
        """
        h_prev = calculate_shannon_entropy(previous_bytes) if previous_bytes else 2.5
        h_next = calculate_shannon_entropy(incoming_bytes)
        delta_h = h_next - h_prev

        if delta_h >= 3.0 and h_next >= 7.2:
            msg = f"Cifrado sospechoso en {os.path.basename(file_path)}: Salto Delta H de {delta_h:.2f} (Entropía: {h_next})"
            self._trigger_threat_containment("RANSOMWARE_ENTROPY_ANOMALY", msg)
            return {"hostile": True, "delta_entropy": delta_h, "peak_entropy": h_next}

        return {"hostile": False, "delta_entropy": delta_h, "peak_entropy": h_next}

    def _trigger_threat_containment(self, alert_type: str, details: str):
        """Notifica al callback de seguridad para aislar el proceso y purgar la bóveda."""
        if self.on_threat_detected:
            self.on_threat_detected(alert_type, details)