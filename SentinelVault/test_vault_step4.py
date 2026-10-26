import os
import sys
import psutil
from agent_main import SentinelVaultEndpointAgent
from dlp_guard import ScreenCaptureShield, ProcessPIDGuard, ActiveClipboardShield
from privacy_compliance import PIIScannerISO29100

print("=" * 75)
print("🛡️  SENTINELVAULT - PRUEBA INTEGRAL PASO 4 (DLP + PID GUARD + AGENT CORE)")
print("=" * 75)

# 1. Arrancar el Agente Unificado
agent = SentinelVaultEndpointAgent()
startup_report = agent.startup()

print("\n[1] ARRANQUE DEL AGENTE UNIFICADO SENTINELVAULT:")
for k, v in startup_report.items():
    print(f"    {k:24} : {v}")

# 2. Validación de Protección Anti-Capturas de Pantalla (SetWindowDisplayAffinity)
print("\n[2] PRUEBA DE PANTALLA NEGRA ANTI-CAPTURAS (WDA_MONITOR):")
dummy_hwnd = 0x1004A  # HWND simulado de ventana de bóveda
screen_protected = ScreenCaptureShield.protect_hwnd(dummy_hwnd)
print(f"    HWND Protegido           : {hex(dummy_hwnd)}")
print(f"    Canal SetWindowDisplay   : {'✅ ACTIVO (WDA_MONITOR / Pantalla Negra)' if screen_protected else '❌ ERROR'}")

# 3. Validación de Micro-DLP por Proceso Invocador (PID Inspection)
print("\n[3] PRUEBA DE MICRO-DLP POR PROCESO (PID INSPECTION):")
current_pid = os.getpid()

# Evaluar proceso actual (Python)
check_current = agent.pid_guard.inspect_process(current_pid)
print(f"    Proceso Evaluador (PID {current_pid}) : {check_current['name']} -> Acción: {check_current['action']}")

# Simular proceso no autorizado intentando abrir la bóveda (ej: powershell o script)
fake_unauthorized_guard = ProcessPIDGuard(allowed_processes={"excel.exe", "winword.exe"})
check_blocked = fake_unauthorized_guard.inspect_process(current_pid)
print(f"    Intento Hostil Simulado           : {check_blocked['name']} -> Acción: 🛑 {check_blocked['action']}")

# 4. Validación de Smart Clipboard Guard (Enmascaramiento en el aire de PII Ley 21.719)
print("\n[4] PRUEBA DE SMART CLIPBOARD GUARD (LEY 21.719):")
texto_copiado_usuario = (
    "Copiando datos de cliente: Juan Pérez - RUT: 11.111.111-1 - Fono: +56912345678"
)
sanitizado, fue_modificado = agent.clipboard_shield.inspect_and_sanitize(texto_copiado_usuario)

print(f"    Texto Original en Portapapeles : {texto_copiado_usuario}")
print(f"    Fuga Interceptada en el Aire   : {'✅ SÍ (RUT Chileno Detectado)' if fue_modificado else '❌ NO'}")
print(f"    Texto Sanitizado al Pegar      : {sanitizado}")

# 5. Cierre ordenado y purga
print("\n[5] CIERRE ORDENADO Y PURGA DE BÓVEDA:")
agent.shutdown()
print(f"    Estado Final de la Bóveda      : {'BLOQUEADA Y PURGADA' if not agent.guardian.is_unlocked else 'ABIERTA'}")
print(f"    Incidentes DLP Mitigados       : {agent.clipboard_shield.sanitized_incidents_count}")

print("=" * 75)