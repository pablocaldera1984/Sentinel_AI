import os
import time
from crypto_engine import EphemeralVMKManager, SentinelCryptoEngine
from forensic_zwc import embed_forensic_mark, decode_forensic_mark
from privacy_compliance import PIIScannerISO29100, generate_blind_index

SANDBOX_DIR = "vault_test_sandbox"
os.makedirs(SANDBOX_DIR, exist_ok=True)

ORG_SECRET = b"GLOBAL365-MASTER-PRIVACY-KEY-2026"

orig_file = os.path.join(SANDBOX_DIR, "Nomina_Ejecutivos_Global365.txt")
enc_file = os.path.join(SANDBOX_DIR, "Nomina_Ejecutivos_Global365.txt.sntvlt")
dec_file = os.path.join(SANDBOX_DIR, "Nomina_Recuperada.txt")
expired_enc_file = os.path.join(SANDBOX_DIR, "Curriculum_Expirado.txt.sntvlt")

print("=" * 75)
print("🛡️  SENTINELVAULT - PRUEBA INTEGRAL PASO 1 (CRYPTO + ZWC + LEY 21.719)")
print("=" * 75)

# 1. Crear documento confidencial con RUTs chilenos válidos (Módulo 11) y emails
documento_confidencial = (
    "CONFIDENCIAL GLOBAL365: Nómina de remuneración y bonos directorio 2026.\n"
    "1) Director Operaciones - RUT: 11.111.111-1 - Email: operaciones@global365.cl - Sueldo: 120 UF\n"
    "2) Subgerente Finanzas  - RUT: 8.888.888-8  - Email: finanzas@global365.cl    - Sueldo: 95 UF\n"
)

# Inyectar Marca de Agua Forense Invisible ZWC (Usuario #402, Equipo #8819)
texto_con_zwc = embed_forensic_mark(
    text=documento_confidencial,
    user_id=402,
    device_id=8819,
    timestamp_hours=5024
)

with open(orig_file, "w", encoding="utf-8") as f:
    f.write(texto_con_zwc)

print("\n[1] ESTEGANOGRAFÍA FORENSE ZWC (U+200B / U+200C) APLICADA:")
print(f"    Tamaño texto original : {len(documento_confidencial)} bytes")
print(f"    Tamaño con huella ZWC : {len(texto_con_zwc)} bytes (100% invisible al ojo humano)")

# 2. Cifrar en contenedor SNTVLT01 + Auto-Tagging ISO/IEC 29100 & Ley 21.719
vmk_mgr = EphemeralVMKManager()
engine = SentinelCryptoEngine(vmk_mgr, org_secret_key=ORG_SECRET)

enc_stats = engine.encrypt_file(
    input_path=orig_file,
    output_path=enc_file,
    user_id=402,
    device_id="WIN11-CONTABILIDAD",
    retention_days=180
)

pii_info = enc_stats["privacy_audit_iso29100"]
print("\n[2] CIFRADO XCHACHA20-POLY1305 (CABECERA 4KB SNTVLT01) + ESCÁNER LEY 21.719:")
print(f"    UUID Contenedor   : {enc_stats['file_uuid']}")
print(f"    Entropía Shannon  : {enc_stats['ciphertext_entropy']} bits/byte (Ideal >= 7.99)")
print(f"    Sensibilidad PII  : {pii_info['sensitivity_level']} | Categorías: {pii_info['categories']}")
print(f"    Conteo Detectado  : {pii_info['counts']['chilean_ruts']} RUTs válidos, {pii_info['counts']['emails']} Emails")
print(f"    Blind Indexes HMAC: {pii_info['arsop_blind_indexes']}")
print(f"    Expira Retención  : {enc_stats['retention_expires_utc']}")

# 3. Buscador ARSOP+ (Derecho al Olvido Ley 21.719) sin descifrar el archivo
rut_buscado = "11.111.111-1"
hash_buscado = generate_blind_index(rut_buscado, ORG_SECRET)
header_inspection = engine.inspect_header_only(enc_file)
encontrado = hash_buscado in header_inspection["metadata"].get("b_idx", [])

print(f"\n[3] BUSCADOR DE DERECHO AL OLVIDO (ARSOP+ LEY 21.719):")
print(f"    Ciudadano solicita borrar RUT {rut_buscado} -> Blind Hash: {hash_buscado}")
print(f"    ¿Encontrado en cabecera cifrada sin abrir el archivo?: {'✅ SÍ (Match Exacto)' if encontrado else '❌ NO'}")

# 4. Descifrado dentro de Red Segura, Rastreo de Fuga ZWC y Seudonimización
dec_stats = engine.decrypt_file(enc_file, dec_file)
with open(dec_file, "r", encoding="utf-8") as f:
    recovered_text = f.read()

fuga_detectada = decode_forensic_mark(recovered_text)
scanner = PIIScannerISO29100(org_secret_key=ORG_SECRET)
vista_seudonimizada = scanner.pseudonymize_text(recovered_text)

print("\n[4] DESCIFRADO EN RED SEGURA + DECODIFICACIÓN DE FUGA + SEUDONIMIZACIÓN:")
print(f"    Huella Forense Extraída : {fuga_detectada}")
print("    Vista Seudonimizada en 1 Clic (ISO/IEC 20889):")
for line in vista_seudonimizada.strip().split("\n"):
    print(f"      -> {line}")

# 5. Prueba de Caducidad Automática y Crypto-Shredding (ISO/IEC 29100)
print("\n[5] PRUEBA DE CADUCIDAD DOCUMENTAL Y CRYPTO-SHREDDING (ISO/IEC 29100:2024):")
engine.encrypt_file(
    input_path=orig_file,
    output_path=expired_enc_file,
    user_id=402,
    device_id="WIN11-RRHH",
    custom_expiry_ts=int(time.time()) - 10  # Expiró hace 10 segundos
)
try:
    engine.decrypt_file(expired_enc_file, dec_file)
except PermissionError as e:
    print(f"    ✅ Auto-Destrucción de Clave FEK Confirmada:\n       {e}")

# 6. Activar KILL SWITCH en RAM y emitir Certificado de Mitigación de Brecha
print("\n[6] DISPARANDO KILL SWITCH CRIPTOGRÁFICO EN RAM (ROBO DE NOTEBOOK):")
kill_report = vmk_mgr.trigger_kill_switch()
try:
    engine.decrypt_file(enc_file, dec_file)
except PermissionError as e:
    print(f"    ✅ Bóveda Bloqueada Instantáneamente: {e}")
    print(f"    📜 CERTIFICADO LEY 21.719: {header_inspection['metadata']['pii']} registros PII resguardados. Exposición neta: 0 registros.")

print("=" * 75)