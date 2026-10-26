import os
import time
from vault_manager import SentinelVaultGuardian
from network_trust import get_public_wan_ip, get_default_gateway_ip, get_gateway_mac_address

BASE_DIR = "vault_test_sandbox"
DESKTOP_VAULT = os.path.join(BASE_DIR, "Desktop_SentinelVault")
BACKING_STORE = os.path.join(BASE_DIR, "EncryptedStore_ProgramData")

# 1. Obtener la telemetría real del entorno local para definir la "Red Segura Autorizada"
real_wan = get_public_wan_ip()
real_gw_ip = get_default_gateway_ip()
real_gw_mac = get_gateway_mac_address(real_gw_ip)

POLICY_CORP = {
    "authorized_wan_ips": [real_wan],
    "authorized_gateway_mac": real_gw_mac,
    "authorized_lan_prefix": "192.168.",
    "required_trust_threshold": 0.80,
    "kill_switch_active": False
}

print("=" * 75)
print("🛡️  SENTINELVAULT - PRUEBA INTEGRAL PASO 2 (GUARDIÁN + CANARIES + ZERO-TRUST)")
print("=" * 75)

# 2. Inicializar el Guardián y sembrar Canaries
guardian = SentinelVaultGuardian(
    vault_desktop_path=DESKTOP_VAULT,
    encrypted_store_path=BACKING_STORE,
    policy=POLICY_CORP
)

print("\n[1] BÓVEDA Y CANARIES ANTI-RANSOMWARE INICIALIZADOS:")
print(f"    Ruta Escritorio        : {DESKTOP_VAULT}")
print(f"    Almacén Cifrado (Store): {BACKING_STORE}")
canary_files = [f for f in os.listdir(DESKTOP_VAULT) if f.startswith("!") or f.startswith("~") or f.startswith("zz")]
print(f"    Archivos Trampa Activos: {canary_files}")

# 3. Desbloqueo evaluando la Ecuación de Confianza Zero-Trust
unlock_res = guardian.unlock_vault()
print("\n[2] EVALUACIÓN DE CONTEXTO DE RED SEGURA S_trust(t):")
print(f"    Estado de Bóveda       : {unlock_res['status']}")
print(f"    Puntaje de Confianza   : {unlock_res.get('score_trust')}")
print(f"    IP WAN Detectada       : {real_wan}")
print(f"    MAC Gateway L2 (ARP)   : {real_gw_mac}")

# 4. Usuario guarda un documento confidencial en Desktop/SentinelVault
doc_name = "Planilla_Sueldos_Octubre.xlsx"
doc_path = os.path.join(DESKTOP_VAULT, doc_name)
with open(doc_path, "w", encoding="utf-8") as f:
    f.write("CONFIDENCIAL: Gerencia 150 UF | Operaciones 110 UF | RUT: 11.111.111-1")

print(f"\n[3] USUARIO GUARDA DOCUMENTO EN BÓVEDA ({doc_name}):")
sync_res = guardian.sync_and_encrypt_document(doc_name)
print(f"    Estado de Sincronización : {sync_res['status']}")
print(f"    UUID en EncryptedStore   : {sync_res['uuid']}")
print(f"    Entropía Cifrada         : {sync_res['entropy']} bits/byte")
print(f"    PII Detectado (Ley 21719): {sync_res['pii_detected']}")

# 5. Simulación: El computador sale de la oficina (cambio de red / IP extraña)
print("\n[4] SIMULACIÓN: EL NOTEBOOK SALE DE LA RED SEGURA CORPORATIVA:")
guardian.network_validator.policy["authorized_wan_ips"] = ["185.220.101.5"]  # Simula IP no autorizada
audit_check = guardian.audit_cycle()
print(f"    Resultado de Auditoría   : Bóveda Activa = {audit_check['active']}")
print(f"    Causa del Bloqueo        : {audit_check['reason']}")
archivos_en_escritorio = os.listdir(DESKTOP_VAULT)
print(f"    Archivos en Escritorio   : {archivos_en_escritorio} (Documento confidencial purgado)")
archivos_cifrados = os.listdir(BACKING_STORE)
print(f"    Archivos en Store Seguro : {archivos_cifrados} (Resguardado con cabecera SNTVLT01)")

# 6. Simulación de Ataque: Un malware intenta modificar un archivo Canary
print("\n[5] SIMULACIÓN DE ATAQUE: MALWARE INTENTA CIFRAR UN CANARY FILE:")
# Restaurar red para volver a abrir la bóveda y sembrar el ataque
guardian.network_validator.policy["authorized_wan_ips"] = [real_wan]
guardian.unlock_vault()

canary_target = os.path.join(DESKTOP_VAULT, "!00_Claves_Tesoreria_2026.xlsx")
# El malware intenta sobrescribir el señuelo con bytes aleatorios
with open(canary_target, "wb") as f:
    f.write(os.urandom(1024))

tamper_res = guardian.canary_guard.verify_canary_integrity()
print(f"    Compromiso Detectado     : {tamper_res['compromised']}")
print(f"    Vector de Ataque         : {tamper_res.get('vector')}")
print(f"    Estado Final de la Bóveda: {'BLOQUEADA Y PURGADA' if not guardian.is_unlocked else 'ABIERTA'}")

print("=" * 75)