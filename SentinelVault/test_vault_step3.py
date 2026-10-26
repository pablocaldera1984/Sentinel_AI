import os
import time
from vault_manager import SentinelVaultGuardian
from vault_backend_service import FIRESTORE_DB_MOCK, trigger_admin_kill_switch
from vault_cloud_sync import CloudLeaseClient
from network_trust import get_public_wan_ip, get_default_gateway_ip, get_gateway_mac_address

BASE_DIR = "vault_test_sandbox"
DESKTOP_VAULT = os.path.join(BASE_DIR, "Desktop_SentinelVault")
BACKING_STORE = os.path.join(BASE_DIR, "EncryptedStore_ProgramData")

# 1. Configurar Firestore con la telemetría real del entorno local
real_wan = get_public_wan_ip()
real_gw_ip = get_default_gateway_ip()
real_gw_mac = get_gateway_mac_address(real_gw_ip)

DEVICE_ID = "WIN11-OFFICE-8819"
FIRESTORE_DB_MOCK[DEVICE_ID]["authorized_wan_cidrs"] = [real_wan]
FIRESTORE_DB_MOCK[DEVICE_ID]["authorized_gateway_mac"] = real_gw_mac

POLICY_CORP = {
    "authorized_wan_ips": [real_wan],
    "authorized_gateway_mac": real_gw_mac,
    "authorized_lan_prefix": "192.168.",
    "required_trust_threshold": 0.80,
    "kill_switch_active": False
}

print("=" * 75)
print("🛡️  SENTINELVAULT - PRUEBA INTEGRAL PASO 3 (CLOUD RUN + FIRESTORE SYNC)")
print("=" * 75)

# 2. Inicializar el Guardián y el Cliente de Nube
guardian = SentinelVaultGuardian(
    vault_desktop_path=DESKTOP_VAULT,
    encrypted_store_path=BACKING_STORE,
    policy=POLICY_CORP
)

cloud_client = CloudLeaseClient(guardian=guardian, device_id=DEVICE_ID)

# 3. Solicitar Arrendamiento Criptográfico al Backend
print("\n[1] SOLICITANDO ARRENDAMIENTO CRIPTOGRÁFICO A FASTAPI / CLOUD RUN:")
lease_res = cloud_client.request_new_lease()
print(f"    Estado de Arrendamiento : {lease_res['status']}")
print(f"    Puntuación Zero-Trust   : {lease_res['trust_score']}")
print(f"    TTL Otorgado            : {lease_res['ttl_seconds']} segundos (15 min)")
print(f"    Bóveda Desbloqueada     : {'✅ SÍ (VMK en RAM)' if guardian.is_unlocked else '❌ NO'}")

# 4. Iniciar Escucha Persistente de Firestore en Tiempo Real
cloud_client.start_realtime_firestore_listener()
print("\n[2] CANAL PUSH FIRESTORE ACTIVO:")
print("    Escuchando cambios en organizations/ORG-VALPO-2026/endpoints/WIN11-OFFICE-8819...")

# 5. Guardar archivo en la bóveda con la clave autorizada por la nube
doc_name = "Presupuesto_Corporativo_2026.xlsx"
doc_path = os.path.join(DESKTOP_VAULT, doc_name)
with open(doc_path, "w", encoding="utf-8") as f:
    f.write("CONFIDENCIAL GLOBAL365: Presupuesto anual de ciberseguridad 600 UF.")

sync_res = guardian.sync_and_encrypt_document(doc_name)
print(f"\n[3] ARCHIVO SINCRONIZADO Y RESGUARDADO CON CLAVE DE NUBE:")
print(f"    Documento       : {doc_name}")
print(f"    UUID Cifrado    : {sync_res['uuid']}")
print(f"    Almacén Seguro  : {sync_res['status']}")

# 6. Simular disparo de Kill Switch desde portal_admin.html en la nube
print("\n[4] ADMINISTRADOR ACTIVA KILL SWITCH EN PORTAL_ADMIN.HTML:")
import asyncio
asyncio.run(trigger_admin_kill_switch(device_id=DEVICE_ID, active=True))

# Breve espera de 1 segundo para observar la interrupción push
time.sleep(1.0)

print(f"\n[5] ESTADO TRAS EL PUSH DE REVOCACIÓN REMOTA:")
print(f"    Bóveda Activa           : {guardian.is_unlocked}")
print(f"    Archivos en Escritorio  : {os.listdir(DESKTOP_VAULT)} (Documento sensible purgado)")
print(f"    Backing Store Cifrado   : {os.listdir(BACKING_STORE)} (Protegido)")

cloud_client.stop_listener()
print("\n" + "=" * 75)