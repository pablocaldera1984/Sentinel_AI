import os
import json
import time
import struct
import uuid
import math
import ctypes
from collections import Counter
from datetime import datetime, timezone
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
import hashlib
import hmac
from privacy_compliance import PIIScannerISO29100

# Constantes de Arquitectura de Almacenamiento SentinelVault
MAGIC_SIGNATURE = b"SNTVLT01"          # 8 bytes (0x0000 - 0x0007)
HEADER_SIZE = 4096                     # 4 KB alineado a página NTFS
CHUNK_PLAINTEXT_SIZE = 65536           # 64 KB lógicos por bloque
NONCE_SIZE = 24                        # 192 bits para XChaCha20
MAC_TAG_SIZE = 16                      # 128 bits Poly1305 Tag
CHUNK_PHYSICAL_SIZE = NONCE_SIZE + CHUNK_PLAINTEXT_SIZE + MAC_TAG_SIZE  # 65,576 bytes


def calculate_shannon_entropy(data: bytes) -> float:
    """Calcula la Entropía de Shannon H(X) en bits/byte (rango 0.0 a 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(entropy, 4)


class EphemeralVMKManager:
    """
    Custodia la Clave Maestra Efímera (VMK - Nivel 2) exclusivamente en memoria RAM.
    Soporta destrucción instantánea (Kill Switch / ISO 27040 Cryptographic Erase).
    """
    def __init__(self, vmk_bytes: bytes = None):
        raw_key = vmk_bytes if vmk_bytes else os.urandom(32)
        if len(raw_key) != 32:
            raise ValueError("La clave VMK debe tener exactamente 32 bytes (256 bits).")
        self._vmk_buffer = bytearray(raw_key)
        self.is_active = True
        self.revoked_at_utc = None

    def get_key(self) -> bytes:
        if not self.is_active:
            raise PermissionError(
                f"ACCESO DENEGADO: Clave VMK purgada de la memoria RAM (Kill Switch ejecutado en {self.revoked_at_utc})."
            )
        return bytes(self._vmk_buffer)

    def trigger_kill_switch(self) -> dict:
        """Sobrescribe el búfer de la clave en RAM con ceros (SecureZeroMemory)."""
        buf_len = len(self._vmk_buffer)
        ctypes.memset((ctypes.c_char * buf_len).from_buffer(self._vmk_buffer), 0, buf_len)
        for i in range(buf_len):
            self._vmk_buffer[i] = 0
        self.is_active = False
        self.revoked_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "status": "VMK_DESTROYED_IN_RAM",
            "standard": "ISO/IEC 27040:2024 Cryptographic Erase",
            "revoked_at_utc": self.revoked_at_utc
        }


class SentinelCryptoEngine:
    """
    Motor de Cifrado AEAD por Bloques (64 KB) con Cabecera Propietaria de 4 KB,
    Auto-Tagging PII (Ley 21.719) y Retención con Crypto-Shredding (ISO 29100).
    """
    def __init__(self, vmk_manager: EphemeralVMKManager, org_secret_key: bytes = b"GLOBAL365-SECRET-2026"):
        self.vmk_manager = vmk_manager
        self.pii_scanner = PIIScannerISO29100(org_secret_key=org_secret_key)

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        user_id: int = 1,
        device_id: str = "WIN11-NODE",
        retention_days: int = 365,
        custom_expiry_ts: int = None
    ) -> dict:
        vmk = self.vmk_manager.get_key()
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Archivo no encontrado: {input_path}")

        logical_size = os.path.getsize(input_path)
        file_uuid = uuid.uuid4().bytes  # 16 bytes (0x0008 - 0x0017)
        fek = os.urandom(32)            # Clave única por archivo (FEK - Nivel 3)

        # Escaneo automático de PII (ISO 29100 / Ley 21.719) sobre contenido legible
        with open(input_path, "rb") as f_scan:
            raw_sample = f_scan.read(512 * 1024)  # Muestra rápida de primeros 512 KB
        text_sample = raw_sample.decode("utf-8", errors="ignore")
        pii_report = self.pii_scanner.scan_text(text_sample)

        now_ts = int(time.time())
        exp_ts = custom_expiry_ts if custom_expiry_ts is not None else (now_ts + (retention_days * 86400))

        # Construir metadatos forenses y de privacidad compactos para caber en 256 bytes (0x0068 - 0x0167)
        compact_meta = {
            "u": user_id,
            "d": device_id[:16],
            "exp": exp_ts,
            "sens": pii_report["sensitivity_level"][0],  # C=CRITICAL, H=HIGH, L=LOW
            "ruts": pii_report["counts"]["chilean_ruts"],
            "pii": pii_report["counts"]["total_pii_records"],
            "b_idx": pii_report["arsop_blind_indexes"][:4]  # Hasta 4 hashes cortos en cabecera local
        }
        meta_bytes = json.dumps(compact_meta, separators=(",", ":")).encode("utf-8")
        meta_padded = meta_bytes[:256].ljust(256, b"\x00")

        # 1. Envolver FEK con VMK (72 bytes: 24B Nonce + 32B Cipher + 16B Tag)
        fek_nonce = os.urandom(NONCE_SIZE)
        wrapped_fek = crypto_aead_xchacha20poly1305_ietf_encrypt(
            message=fek,
            aad=file_uuid + meta_padded,  # Vincula metadatos ISO 29100 como AAD inmutable
            nonce=fek_nonce,
            key=vmk
        )
        wrapped_fek_slot = fek_nonce + wrapped_fek  # 72 bytes

        # 2. Relleno aleatorio de alta entropía (3704 bytes: 0x0168 - 0x0FDF)
        reserved_padding = os.urandom(3704)

        header_body = (
            MAGIC_SIGNATURE +                   # 8 B
            file_uuid +                         # 16 B
            struct.pack("<Q", logical_size) +   # 8 B
            wrapped_fek_slot +                  # 72 B
            meta_padded +                       # 256 B
            reserved_padding                    # 3704 B
        )
        assert len(header_body) == 4064

        # 3. Etiqueta MAC de integridad de la cabecera (32 bytes: 0x0FE0 - 0x0FFF)
        header_mac = hmac.new(vmk, header_body, hashlib.sha256).digest()
        full_header = header_body + header_mac
        assert len(full_header) == HEADER_SIZE

        # 4. Cifrar el archivo en bloques de 64 KB
        chunks_count = 0
        sample_ciphertext = bytearray()

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(full_header)
            chunk_index = 0
            while True:
                plaintext_chunk = f_in.read(CHUNK_PLAINTEXT_SIZE)
                if not plaintext_chunk:
                    break

                chunk_nonce = os.urandom(NONCE_SIZE)
                chunk_aad = file_uuid + struct.pack("<Q", chunk_index)

                ciphertext_with_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(
                    message=plaintext_chunk,
                    aad=chunk_aad,
                    nonce=chunk_nonce,
                    key=fek
                )
                physical_block = chunk_nonce + ciphertext_with_tag
                f_out.write(physical_block)

                if len(sample_ciphertext) < 65536:
                    sample_ciphertext.extend(physical_block)

                chunk_index += 1
                chunks_count += 1

        del fek

        return {
            "file_uuid": str(uuid.UUID(bytes=file_uuid)),
            "logical_size_bytes": logical_size,
            "physical_size_bytes": os.path.getsize(output_path),
            "chunks_encrypted": chunks_count,
            "ciphertext_entropy": calculate_shannon_entropy(bytes(sample_ciphertext)),
            "privacy_audit_iso29100": pii_report,
            "retention_expires_utc": datetime.fromtimestamp(exp_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }

    def inspect_header_only(self, encrypted_path: str) -> dict:
        """
        Lee los metadatos públicos/forenses de la cabecera de 4 KB sin descifrar el archivo
        (Permite ejecutar búsquedas ARSOP+ de Derecho al Olvido o inventarios RoPA ultrarrápidos).
        """
        with open(encrypted_path, "rb") as f:
            header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE or header[:8] != MAGIC_SIGNATURE:
            raise ValueError("No es un contenedor válido SNTVLT01.")
        file_uuid = str(uuid.UUID(bytes=header[8:24]))
        logical_size = struct.unpack("<Q", header[24:32])[0]
        raw_meta = header[104:360].rstrip(b"\x00").decode("utf-8", errors="ignore")
        return {
            "file_uuid": file_uuid,
            "logical_size_bytes": logical_size,
            "metadata": json.loads(raw_meta) if raw_meta.startswith("{") else {}
        }

    def crypto_shred_file(self, encrypted_path: str) -> dict:
        """
        Destruye de forma irreversible el slot de la clave FEK (bytes 32 a 104) en la cabecera
        del archivo sin necesidad de borrar ni reescribir megabytes de bloques cifrados (ISO 29100 / 27040).
        """
        with open(encrypted_path, "r+b") as f:
            f.seek(32)
            f.write(b"\x00" * 72)  # Purga el Wrapped_FEK_Slot con ceros
            f.flush()
        return {
            "action": "CRYPTO_SHREDDED",
            "file": encrypted_path,
            "status": "FEK_SLOT_DESTROYED_IRREVERSIBLY"
        }

    def decrypt_file(self, encrypted_path: str, output_path: str) -> dict:
        vmk = self.vmk_manager.get_key()

        with open(encrypted_path, "rb") as f_in:
            header = f_in.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE or header[:8] != MAGIC_SIGNATURE:
                raise ValueError("Archivo corrupto o firma mágica SNTVLT01 inválida.")

            header_body = header[:4064]
            header_mac = header[4064:4096]
            wrapped_fek_slot = header[32:104]

            # Verificar si el archivo fue sometido a Crypto-Shredding (Derecho al Olvido / Expiración)
            if wrapped_fek_slot == b"\x00" * 72:
                raise PermissionError(
                    "CRYPTO-SHREDDED (ISO/IEC 29100): La clave única (FEK) de este documento fue destruida permanentemente."
                )

            expected_mac = hmac.new(vmk, header_body, hashlib.sha256).digest()
            if not hmac.compare_digest(header_mac, expected_mac):
                raise PermissionError("Fallo de integridad HMAC en cabecera: Clave VMK inválida o archivo manipulado.")

            file_uuid = header[8:24]
            logical_size = struct.unpack("<Q", header[24:32])[0]
            meta_padded = header[104:360]
            meta_json = json.loads(meta_padded.rstrip(b"\x00").decode("utf-8"))

            # Validar Política de Retención y Caducidad (ISO/IEC 29100:2024)
            now_ts = int(time.time())
            if now_ts > meta_json.get("exp", now_ts + 1):
                f_in.close()
                self.crypto_shred_file(encrypted_path)
                raise PermissionError(
                    "RETENCIÓN EXPIRADA (ISO/IEC 29100 / Ley 21.719): El plazo legal del archivo venció y se aplicó Crypto-Shredding automático."
                )

            # Desenvolver FEK usando la VMK en RAM
            fek_nonce = wrapped_fek_slot[:NONCE_SIZE]
            wrapped_fek = wrapped_fek_slot[NONCE_SIZE:]
            fek = crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext=wrapped_fek,
                aad=file_uuid + meta_padded,
                nonce=fek_nonce,
                key=vmk
            )

            bytes_written = 0
            chunk_index = 0
            with open(output_path, "wb") as f_out:
                while True:
                    physical_block = f_in.read(CHUNK_PHYSICAL_SIZE)
                    if not physical_block:
                        break

                    chunk_nonce = physical_block[:NONCE_SIZE]
                    ciphertext_with_tag = physical_block[NONCE_SIZE:]
                    chunk_aad = file_uuid + struct.pack("<Q", chunk_index)

                    plaintext_chunk = crypto_aead_xchacha20poly1305_ietf_decrypt(
                        ciphertext=ciphertext_with_tag,
                        aad=chunk_aad,
                        nonce=chunk_nonce,
                        key=fek
                    )
                    f_out.write(plaintext_chunk)
                    bytes_written += len(plaintext_chunk)
                    chunk_index += 1

        del fek
        return {
            "file_uuid": str(uuid.UUID(bytes=file_uuid)),
            "restored_size_bytes": bytes_written,
            "expected_size_bytes": logical_size,
            "forensic_header_meta": meta_json
        }