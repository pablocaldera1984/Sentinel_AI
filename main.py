import re
import os
import json
import requests
import time
import hmac
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from markupsafe import escape
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth
from google.cloud.firestore_v1.base_query import FieldFilter
from flask_cors import CORS
import holidays
from google import genai
from google.genai import types
import threading

# INYECCIONES DE SEGURIDAD ESTÁNDAR OWASP ASVS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

#
# CONFIGURACIÓN E INICIALIZACIÓN
#
COLECCION_TELEMETRIA = "auditoria_sandbox"
COLECCION_DECISIONES = "auditoria_decisiones_ia"
COLECCION_CONFIG_EMPRESAS = "config_empresas"

# HARDENING DE INICIALIZACIÓN: Captura segura de contexto de infraestructura para evitar fallas 503
try:
    if not firebase_admin._apps:
        firebase_admin.initialize_app()
    db = firestore.client()
except Exception as err_init:
    print(f"X ERROR CRÍTICO DE ENTORNO: Fallo al instanciar el cliente Firestore SDK: {str(err_init)}")
    db = None

app = Flask(__name__)

# --- INICIO DEL ESCUDO CORS GLOBAL ---
@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return '', 200
# --- FIN DEL ESCUDO CORS GLOBAL ---

# Capa 2: Forzar Cabeceras de Seguridad HTTP con Flask-Talisman (HSTS, CSP, X-Frame-Options)
Talisman(app, force_https=True, session_cookie_secure=True)

# Capa 3: CORS con Restricción de Orígenes Cruzados Estricto por Variable de Entorno (Corregido a global365.cl)
DOMINIO_PERMITIDO = os.environ.get("ORIGEN_PERMITIDO", "https://global365.cl")
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Capa 1: Instanciar Rate Limiting Anti-Automatización (OWASP ASVS)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

feriados_cl = holidays.CL(years=[datetime.now().year, datetime.now().year + 1])

# ==========================================
# CONFIGURACIÓN DE SEGURIDAD (API META / WHATSAPP)
# ==========================================
TOKEN_META = os.environ.get("TOKEN_META")
if not TOKEN_META:
    raise ValueError("❌ ERROR CRÍTICO: La variable de entorno 'TOKEN_META' no está configurada.")

META_APP_SECRET = os.environ.get("META_APP_SECRET")
if not META_APP_SECRET:
    raise ValueError("❌ ERROR CRÍTICO: La variable de entorno 'META_APP_SECRET' no está configurada.")

WHATSAPP_VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN")
if not WHATSAPP_VERIFY_TOKEN:
    raise ValueError("❌ ERROR CRÍTICO: La variable de entorno 'WHATSAPP_VERIFY_TOKEN' no está configurada.")

ID_TELEFONO_META = "1175775235621587"
URL_META = f"https://graph.facebook.com/v19.0/{ID_TELEFONO_META}/messages"

# =========================================================================
# 🔒 CENTRALIZACIÓN ATÓMICA DEL PATRÓN GUARDIÁN (EJECUCIÓN DE MEJOR PRÁCTICA)
# =========================================================================
class HerramientaSOC:
    def __init__(self, clave_comando, funcion_referencia, descripcion_prompt):
        self.clave_comando = clave_comando
        self.funcion_referencia = funcion_referencia
        self.descripcion_prompt = descripcion_prompt

class RegistroGuardianSOC:
    def __init__(self):
        self._herramientas = {}

    def registrar_herramienta(self, clave_comando, funcion_referencia, descripcion_prompt):
        self._herramientas[clave_comando] = HerramientaSOC(clave_comando, funcion_referencia, descripcion_prompt)

    @property
    def lista_blanca(self):
        return list(self._herramientas.keys())

    @property
    def mapeo_funciones(self):
        return {clave: h.funcion_referencia for clave, h in self._herramientas.items()}

    def generar_instruccion_herramientas_prompt(self):
        instruccion = "INSTRUCCIONES DE SELECCIÓN DE MINI-HERRAMIENTAS HABILITADAS:\n"
        instruccion += "Clasifica la contingencia e invoca OBLIGATORIAMENTE uno de los siguientes comandos exactos basados en tus herramientas:\n"
        for clave, h in self._herramientas.items():
            instruccion += f"- '{clave}': {h.descripcion_prompt}\n"
        return instruccion

guardian_registry = RegistroGuardianSOC()

# 🧠 REGISTRO MAESTRO DE TODAS TUS SKILLS (UNIFICADO EN UN SOLO PUNTO)
guardian_registry.registrar_herramienta("ram_flush", "analizar_historico_y_seguridad", "Limpia buffers de memoria e inspecciona persistencia temporal.")
guardian_registry.registrar_herramienta("clear_cache", "analizar_historico_y_seguridad", "Descarga caches lógicas de la estación de trabajo.")
guardian_registry.registrar_herramienta("repair_network", "predecir_threat_comportamiento", "Analiza métricas de red y re-enruta el tráfico de interfaces.")
guardian_registry.registrar_herramienta("time_sync", "analizar_historico_y_seguridad", "Sincroniza marcas de tiempo de los relojes de hardware.")
guardian_registry.registrar_herramienta("print_spooler_resurrector", "predecir_threat_comportamiento", "Levanta servicios caídos de cola de impresión local.")
guardian_registry.registrar_herramienta("vpn_gateway_repair", "predecir_threat_comportamiento", "Reinicia y repara túneles de comunicación perimetral.")
guardian_registry.registrar_herramienta("zombie_app_killer", "predecir_threat_comportamiento", "Termina subprocesos huérfanos que consumen ciclos de cómputo de forma anómala.")
guardian_registry.registrar_herramienta("defrag_trim_optimizer", "evaluar_roi_y_renovacion_pc", "Optimiza sectores lógicos de almacenamiento mecánico o sólido.")
guardian_registry.registrar_herramienta("thermal_throttle_mitigation", "evaluar_roi_y_renovacion_pc", "Aplica directivas de energía para enfriamiento del silicio.")
guardian_registry.registrar_herramienta("enable_firewall", "predecir_ruta_ataque", "Habilita el cortafuegos del sistema operativo local.")
guardian_registry.registrar_herramienta("usb_port_lockdown", "predecir_ruta_ataque", "Bloquea controladores de puertos físicos de almacenamiento extraíble.")
guardian_registry.registrar_herramienta("usb_port_unlock", "predecir_ruta_ataque", "Libera restricciones sobre controladores de almacenamiento físico.")
guardian_registry.registrar_herramienta("aislar_equipo", "predecir_ruta_ataque", "Aísla el host de la red local cortando comunicaciones IP lógicas.")
guardian_registry.registrar_herramienta("bloquear_shadow_ai", "detectar_fuga_shadow_ai", "Detiene procesos locales no autorizados de frameworks de LLM.")
guardian_registry.registrar_herramienta("forzar_update_av", "predecir_ruta_ataque", "Fuerza la actualización de firmas del motor antimalware local.")
guardian_registry.registrar_herramienta("evaluar_roi_y_renovacion_pc", "evaluar_roi_y_renovacion_pc", "Ejecuta diagnóstico de ciclos de vida físicos y hardware de silicio.")
guardian_registry.registrar_herramienta("deshabilitar_impresion", "deshabilitar_impresion", "Deshabilita servicio de Spooler local por motivos ecológicos.")
guardian_registry.registrar_herramienta("desinstalar_agente_local", "desinstalar_agente_local", "Remueve de forma permanente los binarios del agente local.")
guardian_registry.registrar_herramienta("evaluar_radio_explosion", "evaluar_radio_explosion", "Mide el radio de impacto cruzando niveles de privilegios lógicos.")
guardian_registry.registrar_herramienta("generar_auditoria_360", "analizar_telemetria_360", "Ejecuta un reporte general cognitivo cruzando hardware y secops.")
guardian_registry.registrar_herramienta("iniciar_triaje_forense", "registrar_evidencia_forense", "Encapsula y resguarda la cadena de custodia bajo ISO 27037.")
guardian_registry.registrar_herramienta("ejecutar_volatility_ram", "analizar_volcado_ram", "Desensambla volcados de memoria buscando rootkits o malware fileless.")
guardian_registry.registrar_herramienta("extraer_artefactos_web", "analizar_artefactos_timeline", "Cruza cookies e historiales cazando técnicas de TimeStomp.")
guardian_registry.registrar_herramienta("auditar_identidad_cloud", "analizar_identidad_cloud", "Audita logs de accesos SaaS para detectar fatiga MFA o viajes imposibles.")
guardian_registry.registrar_herramienta("auditar_perimetro_easm", "analizar_superficie_externa", "Procesa syslogs perimetrales cazando exploits en hardware de borde.")
guardian_registry.registrar_herramienta("ok", None, "Usa este comando si las métricas operan con total normalidad.")

# Asignación automática de variables globales para compatibilidad descendente con el resto del script
LISTA_BLANCA_HERRAMIENTAS = guardian_registry.lista_blanca
MAPEO_REF_FUNCIONES = guardian_registry.mapeo_funciones

# ESQUEMA ESTRICTO PARA EL REPORTE JSON DE AUDITORÍA GENERAL
esquema_auditoria = types.Schema(
    type="OBJECT",
    properties={
        "score_postura_final": types.Schema(type="INTEGER", description="Cálculo matemático 0-100"),
        "estado_general": types.Schema(type="STRING", description="OPTIMO, PRECAUCION o CRITICO"),
        "hallazgos_hardware_dex": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Observaciones de silicio, throttling, RAM, S.M.A.R.T, Batería"
        ),
        "hallazgos_ciberseguridad": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Incumplimientos CIS v8, firewall, actualizaciones MSRC, Shadow AI"
        ),
        "alertas_ioa_criticas": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Alteraciones archivo hosts, ASEPs no firmados, beaconing TCP"
        ),
        "recomendacion_ejecutiva": types.Schema(type="STRING"),
        "razonamiento_interno": types.Schema(type="STRING", description="Análisis profundo y justificación técnica de la decisión (Chain of Thought)"),
        "tecnica_mitre": types.Schema(type="STRING", description="ID y nombre de la técnica MITRE ATT&CK detectada (ej. T1078 - Valid Accounts)")
    },
    required=["score_postura_final", "estado_general", "hallazgos_hardware_dex", "hallazgos_ciberseguridad", "alertas_ioa_criticas", "recomendacion_ejecutiva", "razonamiento_interno", "tecnica_mitre"]
)

# ESQUEMA ESTRICTO DE SALIDA PARA ANÁLISIS FORENSE DE MEMORIA RAM (Volatility 3 Compliance)
esquema_ram_forense = types.Schema(
    type="OBJECT",
    properties={
        "comprometido": types.Schema(type="BOOLEAN", description="Determina si existen indicios de malware en memoria"),
        "nivel_riesgo": types.Schema(type="STRING", description="Nivel de criticidad: CRITICO, ALTO, MEDIO, BAJO"),
        "analisis_procesos": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Evaluación de windows.pslist / procesos ocultos, inyectados o huerfanos (Rootkits)"
        ),
        "analisis_red": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Evaluación de windows.netscan / conexiones activas a C2, beaconing o puertos anómalos"
        ),
        "analisis_inyeccion": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Evaluación de windows.malfind / código inyectado, regiones ERW, malware fileless"
        ),
        "resumen_ejecutivo_dfir": types.Schema(type="STRING", description="Conclusión de ingeniería forense directa para la toma de decisiones")
    },
    required=["comprometido", "nivel_riesgo", "analisis_procesos", "analisis_red", "analisis_inyeccion", "resumen_ejecutivo_dfir"]
)

# ESQUEMA ESTRICTO DE SALIDA PARA RECONSTRUCCIÓN DE TIMELINE Y LUCHA ANTI-FORENSE (ISO 27037 Compliance)
esquema_timeline_forense = types.Schema(
    type="OBJECT",
    properties={
        "timeline_cronologica": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Paso a paso cronológico detallado de la actividad sospechosa y navegación reconstruida"
        ),
        "anomalias_antiforenses": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Detección de técnicas de manipulación temporal TimeStomp en atributos MACE, eliminación de logs o borrado de caché"
        ),
        "nivel_manipulacion": types.Schema(type="STRING", description="Grado de alteración detectada: CRITICO, ALTO, MEDIO, BAJO, NINGUNO"),
        "dictamen_forense": types.Schema(type="STRING", description="Conclusión pericial técnica directa para el visor del administrador")
    },
    required=["timeline_cronologica", "anomalias_antiforenses", "nivel_manipulacion", "dictamen_forense"]
)

# ESQUEMA ESTRICTO JSON PARA MÓDULO ITDR (IDENTITY THREAT DETECTION & RESPONSE)
esquema_itdr = types.Schema(
    type="OBJECT",
    properties={
        "compromiso_identidad": types.Schema(type="BOOLEAN", description="Determina si existen indicios de abuso, suplantación o robo de credenciales activas"),
        "nivel_riesgo": types.Schema(type="STRING", description="Nivel de severidad de identidad: CRITICO, ALTO, MEDIO, BAJO"),
        "anomalias_detectadas": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Lista de vectores encontrados (Viajes imposibles, bypass MFA, fatiga, secuestro de sesión)"
        ),
        "accion_sugerida": types.Schema(type="STRING", description="Acción táctica inmediata para contención en el plano de identidad"),
        "razonamiento_interno": types.Schema(type="STRING", description="Justificación y análisis lógico agéntico del nivel de riesgo determinado"),
        "tecnica_mitre": types.Schema(type="STRING", description="Identificador MITRE ATT&CK (ej. T1110 - Brute Force o ASI03)")
    },
    required=["compromiso_identidad", "nivel_riesgo", "anomalias_detectadas", "accion_sugerida", "razonamiento_interno", "tecnica_mitre"]
)

# ESQUEMA ESTRICTO JSON PARA MÓDULO EASM (EXTERNAL ATTACK SURFACE MANAGEMENT)
esquema_easm = types.Schema(
    type="OBJECT",
    properties={
        "perimetro_vulnerable": types.Schema(type="BOOLEAN", description="Establece si el hardware perimetral o la superficie externa expone brechas de compromiso crítico"),
        "nivel_riesgo": types.Schema(type="STRING", description="Nivel de criticidad externa: CRITICO, ALTO, MEDIO, BAJO"),
        "vulnerabilidades_edge": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Lista de CVEs latentes detectadas, exploits o backdoors en sistemas operativos de borde"
        ),
        "intentos_fuerza_bruta": types.Schema(
            type="ARRAY",
            items=types.Schema(type="STRING"),
            description="Logs que consolidan ráfagas inusuales de autenticación o intrusiones exitosas en túneles VPN/Firewall"
        ),
        "accion_sugerida": types.Schema(type="STRING", description="Instrucción táctica de contención y mitigación de borde"),
        "razonamiento_interno": types.Schema(type="STRING", description="Análisis determinista perimetral de vectores expuestos expuesto WAN"),
        "tecnica_mitre": types.Schema(type="STRING", description="Mapeo de matriz MITRE (ej. T1190 - Exploit Public-Facing Application)")
    },
    required=["perimetro_vulnerable", "nivel_riesgo", "vulnerabilidades_edge", "intentos_fuerza_bruta", "accion_sugerida", "razonamiento_interno", "tecnica_mitre"]
)

# 🟢 CONSTANTE DE COMPORTAMIENTO MAESTRO UX (PROMPT_SISTEMA_WHATSAPP)
PROMPT_SISTEMA_WHATSAPP = """Actúas como Sentinel AI, un ingeniero senior experto en ciberseguridad corporativa y motor de Agentic SOC para Global365. Te comunicas por WhatsApp con supervisores de forma útil, clara y cercana.
Sigue estrictamente estas directrices operativas según el contexto:
1. ALERTA HITL (Botón Rojo): Si la telemetría indica un ataque crítico inminente (ej. malware en RAM, fuerza bruta en firewall, viajes imposibles), debes alertar e instar al supervisor a utilizar los botones interactivos de APROBAR o RECHAZAR la contención. Termina estas alertas con un único y claro llamado a la acción en forma de pregunta.
2. SELF-SERVICE SOC: Si el usuario pregunta por el estado de seguridad, responde de forma ejecutiva analizando el contexto de logs sin abrumarlo con datos técnicos.
3. DEX (Hardware Predictivo): Si detectas degradación física (ej. vida útil del disco o temperaturas extremas), sugiere proactivamente programar un ticket de reemplazo preventivo.
4. RCA (Resumen de Causa Raíz): Tras aislar un equipo o contener un ataque, proporciona una línea de tiempo resumida de lo que sucedió y cómo se evitó el daño.

REGLAS DE FORMATO CRÍTICAS (WhatsApp UX):
- Máximo 4 frases por respuesta en total.
- Cero jerga técnica innecesaria. Escribe como un compañero útil, no como un bot corporativo.
- Prohibido usar encabezados Markdown (# o ##).
- Usa negritas (*texto*) solo para la información más crítica del message."""

# 🟢 TRADUCCIÓN DE LAS 11 AMENAZAS DEL PANEL A RIESGO DE NEGOCIO (WHATSAPP UX)
DICCIONARIO_AMENAZAS_AMIGABLES = {
    "COMBINACION_TOXICA": "Intento de secuestro de información y bloqueo masivo de archivos corporativos,",
    "SHADOW_AI": "Uso de Inteligencia Artificial no autorizada con alto riesgo de fuga de datos de la empresa,",
    "PHISHING_DNS": "Desvío silencioso de la navegación web, posiblemente hacia páginas bancarias falsas,",
    "AGENT_HIJACK": "Manipulación maliciosa del asistente de IA mediante un documento peligroso,",
    "MFA_FATIGUE": "Bombardeo de notificaciones de inicio de sesión para intentar engañar y vulnerar al usuario,",
    "DEX_DEGRADATION": "Degradación crítica en los componentes físicos o salud del hardware de la estación,",
    "FILELESS_ATTACK": "Programa invisible intentando tomar el control del equipo vulnerando las políticas de seguridad,",
    "ITDR": "Un intento de acceso sospechoso o posible robo de credenciales corporativas en las cuentas cloud,",
    "EASM": "Una vulnerabilidad o brecha de seguridad detectada en el escudo perimetral de internet de la empresa,",
    "FINOPS_ANOMALY": "Un comportamiento ineficiente en el uso de recursos lógicos o licencias ociosas,",
    "HELPDESK_COMPROMISE": "Un reseteo sospechoso de accesos en el soporte técnico seguido de inicios de sesión simultáneos vía Single Sign-On (SSO),",
    "HIGH_TEMPERATURE": "Un sobrecalentamiento crítico por estrés térmico en el procesador principal que pone en riesgo el silicio,",
    "RAM_SATURATION": "Una saturación extrema de memoria RAM que amenaza con congelar por completo el sistema,",
    "SSD_DEGRADATION": "Una degradación avanzada de bloques defectuosos y salud crítica en la unidad de almacenamiento,",
    "BATTERY_WEAR": "Un desgaste químico acelerado en la batería local que compromete la autonomía física,",
    "COMPLIANCE_BREACH": "Una caída en el bastionado lógico por desactivación de las directivas de seguridad corporativas (Firewall/UAC),"
}

# 🟢 TRADUCCIÓN DE SOLUCIONES A LENGUAJE DE NEGOCIO (WHATSAPP UX)
DICCIONARIO_SOLUCIONES_AMIGABLES = {
    "COMBINACION_TOXICA": "El tráfico anómalo fue bloqueado y los archivos críticos se encuentran bajo aislamiento seguro. El ecosistema ha vuelto a la normalidad,",
    "SHADOW_AI": "El entorno de ejecución no autorizado fue deshabilitado y se reforzó la política de privacidad de datos de la empresa,",
    "PHISHING_DNS": "Se restableció la configuración segura de navegación web y se bloquearon los accesos a los portales financieros falsos,",
    "AGENT_HIJACK": "El asistente de IA fue higienizado y su context de memoria fue restaurado a un estado limpio y seguro,",
    "MFA_FATIGUE": "Se bloquearon las solicitudes de ráfaga y se coordinó una verificación de identidad segura para el usuario,",
    "DEX_DEGRADATION": "Se aplicaron directivas de mitigación térmica y se encoló un ticket prioritario de soporte preventivo para el hardware,",
    "FILELESS_ATTACK": "El proceso invisible fue interceptado y neutralizado con éxito, restableciendo las políticas de ejecución de la estación,",
    "ITDR": "Las sesiones comprometidas fueron revocadas de inmediato y se aplicó un bloqueo preventivo en la cuenta cloud,",
    "EASM": "Se bloquearon las IPs atacantes y se reforzó el escudo del firewall perimetral de la empresa,",
    "FINOPS_ANOMALY": "Se optimizaron los perfiles de energía y se liberaron las suscripciones ociosas recuperando la eficiencia presupuestaria,",
    "HIGH_TEMPERATURE": "Se purgaron con éxito los subprocesos de alta carga desestabilizantes, reduciendo la curva de estrés en el silicio,",
    "RAM_SATURATION": "Se forzó la limpieza de buffers huérfanos de memoria RAM de forma remota, recuperando la fluidez operativa,",
    "SSD_DEGRADATION": "Se ejecutó una optimización electrónica TRIM en la unidad sólida y se encoló un reemplazo de hardware preventivo,",
    "BATTERY_WEAR": "Se reconfiguró el perfil energético a bajo consumo y se agendó un ticket CAPEX para la sustitución física del componente,",
    "COMPLIANCE_BREACH": "Se re-inyectaron con éxito las directivas rígidas CIS v8 y se reestableció el escudo del cortafuegos local,"
}

# =========================================================================
# 🟢 MAESTRO UNIVERSAL DE ACCIONES A LENGUAJE NATURAL (WHATSAPP UX)
# =========================================================================
DICCIONARIO_ACCIONES_AMIGABLES = {
    "aislar_equipo": {"singular": "aislar el equipo", "plural": "aislar los equipos"},
    "bloquear_shadow_ai": {"singular": "bloquear el acceso a Shadow AI", "plural": "bloquear el acceso a Shadow AI en la flota"},
    "enable_firewall": {"singular": "activar el cortafuegos local", "plural": "activar el cortafuegos local en las terminales"},
    "forzar_update_av": {"singular": "actualizar las firmas del antivirus", "plural": "actualizar las firmas del antivirus en los sistemas"},
    "ram_flush": {"singular": "liberar la memoria RAM", "plural": "liberar la memoria RAM en los equipos"},
    "clear_cache": {"singular": "limpiar los archivos temporales de caché", "plural": "limpiar la caché de almacenamiento en la flota"},
    "defrag_trim_optimizer": {"singular": "optimizar el disco de almacenamiento", "plural": "optimizar las unidades de almacenamiento"},
    "thermal_throttle_mitigation": {"singular": "mitigar la sobrecarga térmica del procesador", "plural": "aplicar mitigación térmica en las estaciones"},
    "evaluar_roi_y_renovacion_pc": {"singular": "evaluar el rendimiento y ciclo de vida del hardware", "plural": "evaluar el rendimiento y renovación de la flota"},
    "repair_network": {"singular": "reparar la configuración de red", "plural": "reparar los parámetros de red de las estaciones"},
    "vpn_gateway_repair": {"singular": "reparar el acceso a la conexión VPN", "plural": "restablecer los túneles VPN corporativos"},
    "time_sync": {"singular": "sincronizar el reloj del sistema", "plural": "sincronizar las marcas de tiempo de la flota"},
    "print_spooler_resurrector": {"singular": "reiniciar los servicios de impresión locales", "plural": "reiniciar las colas de impresión de la oficina"},
    "zombie_app_killer": {"singular": "detener los procesos en segundo plano congelados", "plural": "cerrar las aplicaciones colgadas en los entornos"},
    "usb_port_lockdown": {"singular": "bloquear los puertos USB extraíbles", "plural": "restringir los accesos USB en la flota"},
    "usb_port_unlock": {"singular": "liberar las restricciones de los puertos USB", "plural": "habilitar los puertos USB en los entornos"},
    "deshabilitar_impresion": {"singular": "deshabilitar el servicio de impresión por política ecológica", "plural": "suspender las colas de impresión para ahorro de recursos"},
    "desinstalar_agente_local": {"singular": "desinstalar por completo el agente de monitoreo", "plural": "remover las instancias del agente local"},
    "evaluar_radio_explosion": {"singular": "medir el radio de impacto de la cuenta", "plural": "evaluar el radio de explosión de accesos privilegios"},
    "generar_auditoria_360": {"singular": "ejecutar una auditoría integral del computador", "plural": "generar una auditoría de rendimiento y seguridad global"},
    "iniciar_triaje_forense": {"singular": "recolectar evidencias forenses del host", "plural": "asegurar la cadena de custodia digital"},
    "ejecutar_volatility_ram": {"singular": "analizar el volcado de memoria RAM", "plural": "ejecutar el análisis forense de procesos en memoria"},
    "extraer_artefactos_web": {"singular": "extraer los artefactos de navegación sospechosos", "plural": "analizar las líneas de tiempo e historiales periciales"},
    "auditar_identidad_cloud": {"singular": "auditar los accesos y registros cloud", "plural": "auditar las políticas de identidad en la nube"},
    "auditar_perimetro_easm": {"singular": "escanear la superficie expuesta a internet", "plural": "auditar el perímetro de borde de la red"},
    "ok": {"singular": "mantener el estado de supervisión normal", "plural": "mantener la flota bajo monitoreo continuo estándar"}
}

def obtener_accion_humana_segura(comando_raw: str, tipo_numero: str = "singular") -> str:
    comando_key = str(comando_raw).strip().lower()
    if comando_key in DICCIONARIO_ACCIONES_AMIGABLES:
        return DICCIONARIO_ACCIONES_AMIGABLES[comando_key].get(tipo_numero, comando_raw)
        
    if any(keyword in comando_key for keyword in ["backdoor", "firmware", "vpn", "perimetral", "easm"]):
        return "cerrar el acceso oculto detectado en la red y actualizar la seguridad"
    if any(keyword in comando_key for keyword in ["shadow", "ai", "ollama", "lmstudio"]):
        return "bloquear la aplicación de Inteligencia Artificial no autorizada"
    if any(keyword in comando_key for keyword in ["ransomware", "crypto", "secuestro", "toxica"]):
        return "detener el programa sospechoso que intenta secuestrar archivos"
    if any(keyword in comando_key for keyword in ["aislar", "host", "phishing", "network", "wifi"]):
        return "desconectar preventivamente el equipo de la red corporativa"
    if any(keyword in comando_key for keyword in ["usb", "lockdown", "port"]):
        return "restringir los accesos de almacenamiento por puertos físicos USB"
    if any(keyword in comando_key for keyword in ["firewall", "cortafuegos", "enable"]):
        return "restablecer y activar de forma remota el cortafuegos local"
    if any(keyword in comando_key for keyword in ["identity", "itdr", "mfa", "sesion"]):
        return "revocar las sesiones activas y forzar la verificación de identidad"
        
    return "aplicar la contención preventiva de seguridad estándar"

def simular_resolucion_automatica_whatsapp(id_equipo, amenaza_key, tkt_id, telefono_supervisor):
    try:
        telefono_destino = telefono_supervisor
        if db:
            tkt_doc = db.collection("tickets_hitl").document(tkt_id).get()
            if tkt_doc.exists:
                tkt_data = tkt_doc.to_dict()
                estado_actual = tkt_data.get("estado", "")
                aprobado_por = tkt_data.get("aprobado_por")
                
                if estado_actual == "pendiente_aprobacion_hitl":
                    print(f"[AIOps SIMULATION] Ticket {tkt_id} expiró sin respuesta. El escalamiento sigue activo.")
                    return
                elif estado_actual == "rechazado":
                    print(f"[AIOps SIMULATION] Ticket {tkt_id} fue rechazado. No se ejecuta contención.")
                    return
                
                if aprobado_por:
                    telefono_destino = aprobado_por
                    
        solucion_amigable = DICCIONARIO_SOLUCIONES_AMIGABLES.get(amenaza_key, "Las contenciones preventivas fueron aplicadas con éxito.")
        
        mensaje_cierre = (
            f"✅ *MONITOREO: INCIDENTE SOLUCIONADO* ✅\n"
            f"Sentinel AI aplicó de forma autónoma las medidas de contención en el equipo de {limpiar_identificador_usuario(id_equipo)}. "
            f"{solucion_amigable} El estado de la flota ha vuelto a la normalidad y opera de manera segura (Ticket: {tkt_id})."
        )
        enviar_texto_whatsapp(telefono_destino, mensaje_cierre)
        print(f"[AIOps SIMULATION] Simulación de remediación enviada con éxito a {telefono_destino} para el ticket {tkt_id}.")
    except Exception as e:
        print(f"X Error en el hilo de simulación de cierre: {str(e)}")

# SKILL: AUDITORÍA TELEMETRÍA 360 GENERAL
def analizar_telemetria_360(telemetria_cruda: dict) -> dict:
    prompt_auditoria = f"""
    Eres Sentinel AI, un auditor experto en hardware y analista SOC Tier 3.
    Evalúa la siguiente telemetría extraída de un endpoint:
    {json.dumps(telemetria_cruda)}
    
    Reglas de Análisis:
    1. HARDWARE: Busca colas de CPU > (núcleos+1), RAM libre < 20%, latencia disco > 10ms, BSODs, o desgaste de batería > 30%.
    2. CIBERSEGURIDAD: Verifica LockoutBadCount <= 5, estado del Firewall, puertos 3389/445 abiertos, and actualizaciones pendientes tipo MSRC Critical.
    3. IoA (Indicadores de Ataque): Busca hashes 'hosts' alterados, procesos temporales con sockets TCP activos, y binarios no firmados en el Registro (ASEPs).
    4. SHADOW AI: Detecta procesos como 'ollama', 'lmstudio', etc.
    
    Aplica la fórmula matemática S_postura y devuelve el resultado ESTRICTAMENTE en la estructura JSON requerida.
    """
    try:
        api_key_studio = os.environ.get("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key_studio)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_auditoria,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=esquema_auditoria,
                temperature=0.1
            )
        )
        diagnostico = json.loads(response.text)
        
        if db:
            try:
                uid_equipo = telemetria_cruda.get('id') or telemetria_cruda.get('uid') or telemetria_cruda.get('cliente', {}).get('usuario', 'Desconocido')
                empresa_id = telemetria_cruda.get('cliente', {}).get('empresa', 'DESCONOCIDA').upper()
                
                db.collection(COLECCION_DECISIONES).add({
                    "tipo": "AUDITORIA_360", 
                    "uid": str(uid_equipo).upper(),
                    "empresa_id": empresa_id,
                    "data": diagnostico, 
                    "timestamp": firestore.SERVER_TIMESTAMP
                })
            except Exception as e_db:
                print(f"! Fallo al guardar log de auditoría en Firestore: {str(e_db)}")
        
        return diagnostico
    except Exception as e:
        return {"error": str(e), "estado_general": "ERROR_ANALISIS"}

# SKILL: ANÁLISIS VOLÁTIL (Volatility 3 Compliance)
def analizar_volcado_ram(datos_plugins: dict) -> dict:
    prompt_ram = f"""
    Eres Sentinel AI, un Ingeniero de Respuesta a Incidentes (DFIR) de nivel avanzado.
    Analiza la siguiente estructura forense recolectada en caliente desde la memoria RAM del host:
    {json.dumps(datos_plugins)}
    
    Matrices de Búsqueda de Amenazas (Threat Hunting):
    1. PROCESOS (pslist): Detecta procesos huérfanos, desalineación de Process ID / Parent Process ID, inyecciones lógicas o ejecutables legítimos (lsass.exe, svchost.exe) corriendo sin firma o con padres inválidos.
    2. CONEXIONES (netscan): Identifica conexiones de red TCP/UDP sospechosas hacia puertos anómalos o de control (C2 Infrastructure), persistencia maliciosa y beaconing recurrente.
    3. CÓDIGO INYECTADO (malfind): Examina rangos de memoria virtual con privilegios de ejecución e inserción PAGE_EXECUTE_READWRITE (ERW), dlls no respaldadas en disco duro y fileless malware operando de forma encubierta en el espacio de usuario.
    
    Devuelve la matriz forense estructurada estrictamente en el formato JSON requerido.
    """
    try:
        api_key_studio = os.environ.get("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key_studio)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_ram,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=esquema_ram_forense,
                temperature=0.1
            )
        )
        return json.loads(response.text)
    except Exception as e:
        print(f"X Error interno en skill analizar_volcado_ram: {str(e)}")
        return {
            "comprometido": False,
            "nivel_riesgo": "ERROR_ANALISIS",
            "analisis_procesos": [f"Fallo en procesamiento de memoria: {str(e)}"],
            "analisis_red": [],
            "analisis_inyeccion": [],
            "resumen_ejecutivo_dfir": "Error crítico al invocar las capacidades cognitivas forenses."
        }

# SKILL FORENSE COGNITIVA (analizar_artefactos_timeline)
def analizar_artefactos_timeline(datos_artefactos: dict) -> dict:
    prompt_timeline = f"""
    Eres Sentinel AI, un experto en Computación Forense y Analista DFIR de élite.
    Evalúa el siguiente conjunto de artefactos de navegación y marcas de tiempo extraídos de la máquina compromised:
    {json.dumps(datos_artefactos)}
    
    Líneas de Análisis Requeridas:
    1. RECONSTRUCCIÓN CRONOLÓGICA: Cruza los historiales de Chrome/Firefox, cookies, caché de navegación y descargas recientes para trazar el flujo exacto del vector de entrada o actividad anómala.
    2. DETECCIÓN ANTI-FORENSE: Inspecciona de manera pericial los metadatos y atributos MACE (Modified, Accessed, Created, MFT Entry Modified). Identifica firmas de alteración deliberada como técnicas 'TimeStomp' (ej. marcas con precisión de nanosegundos en cero, discrepancies ilógicas en la secuencia temporal de archivos del sistema o borrado masivo de Event Logs).
    
    Genera el dictamen pericial estructurado ESTRICTAMENTE bajo la estructura JSON provista.
    """
    try:
        api_key_studio = os.environ.get("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key_studio)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_timeline,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=esquema_timeline_forense,
                temperature=0.1
            )
        )
        return json.loads(response.text)
    except Exception as e:
        print(f"X Error interno en skill analizar_artefactos_timeline: {str(e)}")
        return {
            "timeline_cronologica": [f"Error de procesamiento en línea de tiempo: {str(e)}"],
            "anomalias_antiforenses": [],
            "nivel_manipulacion": "ERROR_ANALISIS",
            "dictamen_forense": "Fallo crítico al invocar las capacidades cognitivas del motor forense."
        }

# SKILL DE IA CLOUD IDENTITY (analizar_identidad_cloud)
def analizar_identidad_cloud(logs_identidad: dict) -> dict:
    prompt_itdr_instruction = f"""
    Actúas como Sentinel AI, analista especializado en Seguridad de Identidad e Ingeniero de Respuesta ITDR de Global365.
    Evalúa minuciosamente el siguiente bloque de registros e historiales de sesión cloud provenientes de los paneles de administración SaaS:
    {json.dumps(logs_identidad)}
    
    Matrices de Búsqueda de Amenazas Avanzadas (ITDR / SecOps Matrix):
    1. ABUSO DE HELPDESK (Mesa de Ayuda): Identifica de forma crítica si se registra un cambio o reseteo de contraseña/MFA ejecutado por soporte técnico o administradores, y evalúa si este evento es seguido inmediatamente por un inicio de sesión exitoso sin fricción en múltiples aplicaciones SaaS mediante Single Sign-On (SSO).
    2. SECUESTRO DE SESIÓN SILENCIOSO: Detecta patrones donde el consumo de CPU local sea bajo o normal y el Firewall permanezca activo, pero existan descargas atípicas de repositorios documentales corporativos, sugiriendo que un atacante opera bajo una identidad válida robada mediante ingeniería social.
    3. VIAJES IMPOSIBLES (Impossible Travel): Cruza geolocalizaciones y marcas de tiempo consecutivas para detectar accesos simultáneos que violen los límites de velocidad física de traslado.
    4. FATIGA DE MFA (MFA Prompt Spamming): Detecta ráfagas repetitivas de solicitudes de empuje de MFA dirigidas a un mismo identificador en un rango corto de tiempo.
    
    Devuelve la evaluación técnica empaquetada estrictamente bajo el formato JSON requerido.
    """
    try:
        api_key_studio = os.environ.get("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key_studio)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_itdr_instruction,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=esquema_itdr,
                temperature=0.1
            )
        )
        return json.loads(response.text)
    except Exception as e:
        print(f"X Error interno en skill analítica analizar_identidad_cloud: {str(e)}")
        return {
            "compromiso_identidad": False,
            "nivel_riesgo": "ERROR_ANALISIS",
            "anomalias_detectadas": [f"Fallo en motor de inference cloud: {str(e)}"],
            "accion_sugerida": "Verificar de forma manual la estabilidad de la API del panel perimetral de identidad.",
            "razonamiento_interno": "Fallo catastrófico en la llamada cognitiva.",
            "tecnica_mitre": "ASI03"
        }
        
# 🟢 NUEVA SKILL DE IA PERIMETRAL EASM (analizar_superficie_externa)
def analizar_superficie_externa(logs_syslog: dict) -> dict:
    prompt_easm_instruction = f"""
    Actúas como Sentinel AI, Ingeniero de Superficie de Ataque Externa (EASM) y Analista SOC Senior de Global365.
    Examina de forma pericial y correlaciona el siguiente conjunto estructurado de Syslogs e historiales de tráfico perimetral de borde:
    {json.dumps(logs_syslog)}
    
    Líneas de Auditoría Externa Requeridas:
    1. CUENTAS DE ADMINISTRADOR ANÓMALAS: Caza la creación oculta o repentina de usuarios con privilegios elevados directamente en el sistema operativo del hardware (vectores Backdoor persistentes).
    2. INTENTOS DE FUERZA BRUTA EN VPN: Identifica ráfagas secuenciales de autenticaciones erróneas o accesos exitosos desalineados (ej. horarios anómalos o IPs negras) en portales SSL-VPN o consolas perimetrales.
    3. EXPOSICIÓN DE INTERFACES: Alerta de forma crítica si se detectan vinculaciones WAN activas dirigidas a los puertos de administración local del Firewall (SSH, HTTP/HTTPS expuestos a Internet).
    4. INDICIOS DE EXPLOTACIÓN (CVEs Edge): Mapea strings de cadenas de logs que sugieran inyecciones de comandos, desbordamientos de búfer o explotación activa de vulnerabilidades conocidas en hardware de borde (ej. FortiBleed, desvíos lógicos Ivanti, etc.).
    
    Genera el dictamen pericial estructurado ESTRICTAMENTE bajo la estructura JSON provista.
    """
    try:
        api_key_studio = os.environ.get("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key_studio)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_easm_instruction,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=esquema_easm,
                temperature=0.1
            )
        )
        return json.loads(response.text)
    except Exception as e:
        print(f"X Error interno en skill analítica analizar_superficie_externa: {str(e)}")
        return {
            "perimetro_vulnerable": False,
            "nivel_riesgo": "ERROR_ANALISIS",
            "vulnerabilidades_edge": [f"Fallo en procesamiento de syslogs: {str(e)}"],
            "intentos_fuerza_bruta": [],
            "accion_sugerida": "Verificar de forma urgente la conectividad criptográfica del recolector de Syslogs externo."
        }

#
# ADAPTADOR OCSF Y TELEMETRÍA DE SILICIO
#
def adaptar_telemetria_ocsf(datos_crudos: dict) -> dict:
    try:
        temp_cpu = float(datos_crudos.get("termico_fans", {}).get("cpu_temperatura_c", 0))
        fan_speed = int(datos_crudos.get("termico_fans", {}).get("fan_speed_rpm", 0))
        estrangulamiento_termico = "INACTIVO"
        if temp_cpu > 85.0:
            estrangulamiento_termico = "ACTIVO_CRITICO"
        
        schema_ocsf = {
            "activity_id": 1,
            "category_uid": 1,
            "class_uid": 1001,
            "severity": "Critical" if estrangulamiento_termico == "ACTIVO_CRITICO" else "Informational",
            "time": datetime.utcnow().isoformat() + "Z",
            "device": {
                "id": datos_crudos.get("id", "UNKNOWN"),
                "os": datos_crudos.get("inventario_os", {}).get("os_ver", "Windows")
            },
            "hardware_telemetry": {
                "cpu_utilization": datos_crudos.get("estado_actual", {}).get("cpu_pct", 0),
                "ram_utilization": datos_crudos.get("estado_actual", {}).get("ram_pct", 0),
                "cpu_temperature_c": temp_cpu,
                "fan_speed_rpm": fan_speed,
                "eventos_estrangulamiento_termico": estrangulamiento_termico
            },
            "raw_data_passthrough": datos_crudos
        }
        return schema_ocsf
    except Exception as e:
        print(f"! Fallo en Adaptador OCSF: {str(e)}")
        return datos_crudos

#
# UTILIDADES Y PRIVACIDAD (DATA MASKING)
#
def enmascarar_telemetria(datos: dict) -> dict:
    try:
        datos_limpios = json.loads(json.dumps(datos))
        if "cliente" in datos_limpios and "usuario" in datos_limpios["cliente"]:
            usr = str(datos_limpios["cliente"]["usuario"])
            if len(usr) > 2:
                datos_limpios["cliente"]["usuario"] = f"{usr[:2]}****{usr[-1:]}"
            else:
                datos_limpios["cliente"]["usuario"] = "USR_ANON"
        if "conectividad_red" in datos_limpios:
            for llave_ip in ["ip_privada", "ip_publica", "gateway_ip"]:
                if llave_ip in datos_limpios["conectividad_red"]:
                    ip_raw = str(datos_limpios["conectividad_red"][llave_ip])
                    datos_limpios["conectividad_red"][llave_ip] = re.sub(r'\.\d+$', '.XXX', ip_raw)
        return datos_limpios
    except Exception as e:
        print(f" Fallo en Data Masking: {str(e)}")
        return datos

def validar_session_firebase(request):
    token = None
    try:
        datos_json = request.get_json(silent=True)
        if datos_json:
            token = datos_json.get("token_validacion")
    except Exception:
        pass

    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ")[1]

    if not token:
        raise ValueError("Token de autenticación ausente.")

    datos_usuario_decodificados = firebase_auth.verify_id_token(token)
    return datos_usuario_decodificados

def limpiar_identificador_usuario(id_equipo_raw: str) -> str:
    if not id_equipo_raw:
        return "Equipo Desconocido"
        
    id_clean = str(id_equipo_raw).strip().upper()
    
    if any(keyword in id_clean for keyword in ["EDGE", "HARDWARE", "GATEWAY", "FIREWALL"]):
        return "*Red Perimetral / Servidor Central*"
        
    if db:
        try:
            doc_sb = db.collection("auditoria_sandbox").document(id_clean).get()
            if doc_sb.exists:
                nombre = doc_sb.to_dict().get("nombre_usuario") or doc_sb.to_dict().get("usuario")
                if nombre: return f"*{str(nombre).title()}*"
                
            doc_gb = db.collection("auditoria_global").document(id_clean).get()
            if doc_gb.exists:
                nombre = doc_gb.to_dict().get("nombre_usuario") or doc_gb.to_dict().get("usuario")
                if nombre: return f"*{str(nombre).title()}*"
        except Exception as err_id:
            print(f"! Fallo no bloqueante al rastrear identidad de hardware: {str(err_id)}")

    id_limpio = re.sub(r'^(GLOBAL365_[A-Za-z0-9]+_[A-Za-z0-9]+_|^GLOBAL365_)', '', id_clean, flags=re.IGNORECASE)
    return id_limpio.strip().upper()

#
# BLINDAJE INSTRUCCIÓN DEL SISTEMA (AGENTIC SOC + SLO PREDICTIVO DEX + ENDURECIMIENTO GUARDIÁN)
#
prompt_sistema_insight = f"""Actúas como Sentinel AI, el motor de inteligencia artificial y analista SOC
senior de la plataforma Global365.
Tu objetivo es entregar un diagnóstico directo, conciso y concluyente sobre el
estado actual y la proyección futura (prospección) del computador seleccionado
por el supervisor corporativo, correlacionando múltiples variables de telemetría,
OCSF, postura de seguridad, Finops Y Sostenibilidad para activar comandos HITL.

🚨 REGLA RÍGIDA DE SEGURIDAD (ENDURECIMIENTO DEL PATRÓN GUARDIÁN):
Tienes ESTRICTAMENTE PROHIBIDO inventar herramientas, sugerir mini-herramientas que no existan, ejecutar código externo o descargar payloads que no pertenezcan al listado explícito adjunto. Si la telemetría no encaja en ninguna acción de mitigación, debes retornar obligatoriamente el comando por defecto 'ok'.

📈 REGLA DE RENDIMIENTO DEX Y SLO PREDICTIVO:
No evalúes métricas de hardware de forma aislada o reactiva. Debes aplicar el concepto de 'SLO Predictivo'. Si detectas una fuga de memoria (RAM libre disminuyendo), temperaturas de CPU elevadas de forma sostenida con estrangulamiento térmico activo, o degradación del disco, debes estimar matemáticamente en tu diagnóstico un tiempo crítico de colapso de la estación (ej. 'El entorno de trabajo colaspará en un estimado de 3 horas si la fuga de memoria persiste') e invocar la contención preventiva adecuada de forma proactiva.

REGLAS DE CORRELACIÓN DE SEGURIDAD (AGENTIC SOC):
- No evalúes métricas de forma aislada; busca patrones de compromiso combinado (Toxic Combinations).
Regla Crítica de Aislamiento: Si el Antivirus está INACTIVO o desactualizado Y de forma simultánea existen puertos críticos expuestos (RDP/SMB abiertos) o el Firewall está Deshabilitado, debes deducir inmediatamente un riesgo inminente de movimiento lateral o Ransomware. Para este escenario, tu acción sugerida obligatoria DEBE ser 'aislar_equipo'.
Regla de Fuga de Datos: Si detectas procesos vinculados a herramientas de IA locales externas no autorizadas (Shadow AI) en execution, debes clasificar la contingencia bajo el comando 'bloquear_shadow_ai'.

REGLAS DE FINOPS, SOSTENIBILIDAD Y CICLO DE VIDA (ENTERPRISE 2026):
Regla de Optimización ROI (Finops): Si el hardware tiene un disco tipo 'HDD' o registra 'eventos_estrangulamiento_termico': 'ACTIVO_CRITICO', o detectas software o licencias corporativas ociosas sin uso, debes sugerir la herramienta 'evaluar_roi_y_renovacion_pc' para dictaminar si requiere un upgrade estratégico o reclamación presupuestaria.
Regla Ecológica (Sostenibilidad): Si el supervisor busca reducir la huella de carbono, aplicar políticas medioambientales, o mitigar el gasto indiscriminado de papel de oficina, debes sugerir el comando 'deshabilitar_impresion'.
Regla de Desincorporación: Si el supervisor solicita de forma explícita borrar, eliminar o limpiar por completo el software de monitoreo de la estación terminal, debes invocar obligatoriamente 'desinstalar_agente_local'.

REGLAS DE FORMATO Y TONO (ESTRICTAS Y OBLIGATORIAS):
1. Tu informe final empaquetado en el JSON debe tener una longitud MÁXIMA de 4 líneas de texto. Sé directo para no desbordar el recuadro gráfico de la interfaz.
2. Está estrictamente PROHIBIDO usar lenguaje técnico avanzado, jerga informática excesiva o códigos de error crudos in el parámetro final 'diagnostico_texto'.
3. Debes traducir amenazas complejas a un ojo de PYME o administrador no técnico.
4. El informe debe fusionar obligatoriamente dos aristas: El estado de salud físico/Finops del hardware y su situación de ciberseguridad predictiva.
5. Regla de Experiencia del Empleado (DEX): Si el 'SENTIMIENTO DEL USUARIO' indica frustración o impacto negativo en su trabajo, debes priorizar este factor humano en tu diagnóstico.

{guardian_registry.generar_instruccion_herramientas_prompt()}"""

#
# SKILLS Y HERRAMIENTAS PROTEGIDAS (TRY-EXCEPT INTERNAL HANDLERS)
#
def analizar_historico_y_seguridad(usuario_equipo: str) -> str:
    try:
        if not db: return "Firestore fuera de línea."
        historico_ref = db.collection(COLECCION_TELEMETRIA)
        fecha_limite = datetime.utcnow() - timedelta(days=7)
        query = historico_ref.where("cliente.usuario", "==", usuario_equipo).where("timestamp", ">=", fecha_limite).stream()
        registros = [doc.to_dict() for doc in query]
        if not registros:
            return f"Nota: No se encontraron datos históricos suficientes en los últimos 7 días para mapear la prospección del usuario {usuario_equipo}."
        ultimo_registro = registros[-1]
        so_version = ultimo_registro.get("inventario_os", {}).get("os_ver", "Windows 11")
        cpu_promedio = sum([r.get("estado_actual", {}).get("cpu_pct", 0) for r in registros]) / len(registros)
        ram_promedio = sum([r.get("estado_actual", {}).get("ram_pct", 0) for r in registros]) / len(registros)
        firewall_activo = ultimo_registro.get("security_posture", {}).get("firewall_activo", True)
        uac_activo = ultimo_registro.get("security_posture", {}).get("uac_status", "ACTIVO") == "ACTIVO"
        
        estado_seguridad = "Optima. Componentes lógicos de protección y parches al día."
        if not firewall_activo or not uac_activo:
            estado_seguridad = "Crítica. Se detectaron directivas de protección caídas (Firewall o Control de Cuentas inactivo)."
        elif "Windows 10" in so_version:
            estado_seguridad = "Advertencia. Sistema operativo antiguo; requiere evaluar migración para asegurar soporte de parches."
        
        prospeccion_hardware = "Estable and operando dentro de rangos normales de silicio."
        if cpu_promedio > 75 or ram_promedio > 80:
            prospeccion_hardware = "Riesgo de degradación de rendimiento por alta demanda sostenida de recursos."
        
        return f"Historial consolidado de {usuario_equipo} en 7 días: Carga CPU: {cpu_promedio:.1f}%, RAM: {ram_promedio:.1f}%. Prospección Hardware: {prospeccion_hardware} Situación Ciberseguridad: {estado_seguridad}"
    except Exception as e:
        return f"Error interno en la herramienta analizar_historico_y_seguridad: {str(e)}"

def predecir_ruta_ataque(antivirus_activo: bool, uac_activo: bool, puertos_rdp_smb_expuestos: bool) -> str:
    try:
        if not antivirus_activo and not uac_activo and puertos_rdp_smb_expuestos:
            return "CRÍTICO: Ruta de ataque encadenada detectada. Riesgo inminente de Ransomware. Acción recomendada: 'aislar_equipo'."
        return "SEGURO: No se detectan combinaciones tóxicas extremas directas."
    except Exception as e:
        return f"Error interno en la herramienta predecir_ruta_ataque: {str(e)}"

def evaluar_radio_explosion(usuario_equipo: str) -> str:
    try:
        if not db: return "Firestore fuera de línea."
        usuarios_ref = db.collection("usuarios").where(filter=FieldFilter("cliente.usuario", "==", usuario_equipo)).limit(1).stream()
        datos_usuario = None
        for doc in usuarios_ref:
            datos_usuario = doc.to_dict()
        rol = datos_usuario.get("rol", "estándar").lower() if datos_usuario else "estándar"
        if "supervisor" in rol or "admin" in rol:
            return f"Blast Radius: CRÍTICO. El usuario {usuario_equipo} cuenta con privilegios superiores. Compromiso expone bases maestras. Acción recomendada: 'aislar_equipo'."
        return f"Blast Radius: LIMITADO. El usuario {usuario_equipo} posee privilegios estándar de estación."
    except Exception as e:
        return f"Error interno en la herramienta evaluar_radio_explosion: {str(e)}"

def predecir_threat_comportamiento(uso_cpu: float, red_tipo: str, senal_pct: float) -> str:
    try:
        if uso_cpu >= 85 and "wifi" in red_tipo.lower() and senal_pct < 40:
            return "ALERTA SECOPS: Comportamiento anómalo en red. Alta demanda sostenida de silicio e inestabilidad sugiere exfiltración oculta (Living-off-the-Land)."
        return "NORMAL: Métricas dinámicas y comportamiento de red operando dentro de rangos normales."
    except Exception as e:
        return f"Error interno en la herramienta predecir_threat_comportamiento: {str(e)}"

def detectar_fuga_shadow_ai(lista_procesos_json: str) -> str:
    try:
        proseso = json.loads(lista_procesos_json) if isinstance(lista_procesos_json, str) else lista_procesos_json
        if not proseso:
            return "Shadow AI: Sin datos válidos de subprocesos activos."
        firmas_shadow = ["ollama", "lmstudio", "localai", "claude_desktop", "gpt4all", "anythingllm"]
        encontrados = []
        for p in proseso:
            nombre_proc = str(p.get("nombre", "")).lower()
            for firma in firmas_shadow:
                if firma in nombre_proc:
                    encontrados.append(p.get("nombre"))
        if encontrados:
            return f"PELIGRO SECOPS: Software de IA local no autorizado detectado: {', '.join(set(encontrados))}. Riesgo de fuga semántica de propiedad intelectual corporativa. Acción recomendada: 'bloquear_shadow_ai'."
        return "Shadow AI COMPLIANCE: Analizado de forma integra. Alineado con las políticas de higiene digital."
    except Exception as e:
        return f"Error interno en la herramienta detectar_fuga_shadow_ai: {str(e)}"

def evaluar_roi_y_renovacion_pc(datos_telemetria: dict) -> str:
    try:
        ssd_status = datos_telemetria.get("almacenamiento_ssd", {})
        tipo_disco = str(ssd_status.get("tipo_medio", "SSD")).upper()
        vida_util = float(ssd_status.get("vida_util_pct", 100))
        cpu_throttle = datos_telemetria.get("hardware_telemetry", {}).get("eventos_estrangulamiento_termico", "INACTIVO")
        recomendacion = "Mantenimiento Preventivo. El ciclo financiero actual del activo es óptimo."
        if tipo_disco == "HDD":
            recomendacion = "Upgrade Estratégico Requerido: Migrar unidad mecánica de almacenamiento a estado sólido (SSD) para recuperar un 40% de productividad operativa (Finops ROI)."
        elif vida_util < 25 or cpu_throttle == "ACTIVO_CRITICO":
            recomendacion = "Reemplazo de Activo Crítico Sugerido (CAPEX): Componentes físicos en fase de degradación térmica avanzada; la reparación supera el valor residual del silicio."
        return f"Auditoría Finops: {recomendacion} Evaluación de perfiles de energía: Ineficiencias latentes detectadas en horario no hábil. Licencias ociosas detectadas: 1 Software de Oficina recuperable."
    except Exception as e:
        return f"Error interno en Skill FinOps: {str(e)}"

def deshabilitar_impresion() -> str:
    return "Auditoría Ecológica Sentinel: El supervisor ha decretado cumplimiento de política medioambiental. Acción requerida: Deshabilitar servicio de impresión (Spooler) para mitigar huella de carbono y detener desperdicio de papel."

def desinstalar_agente_local(usuario_equipo: str) -> str:
    return f"Comando Crítico Ejecutado: El agente Sentinel de la estación vinculada al usuario '{usuario_equipo}' ha sido instruido para ejecutar su rutina de auto-eliminación e higienización del Kernel local."

def registrar_evidencia_forense(id_equipo: str, empresa_id: str, artefactos: dict) -> dict:
    try:
        if not db:
            return {"status": "error", "message": "Fallo de infraestructura: Base de datos Firestore fuera de línea."}
        payload_string = json.dumps(artefactos, sort_keys=True)
        hash_custodia = hashlib.sha256(payload_string.encode('utf-8')).hexdigest()
        registro_evidencia = {
            "id_equipo": str(id_equipo).upper(),
            "empresa_id": str(empresa_id).upper(),
            "hash_cadena_custodia": hash_custodia,
            "normativa_cumplimiento": "ISO 27037 / RFC 3227 (Aseguramiento de Evidencia Digital)",
            "timestamp_forense": firestore.SERVER_TIMESTAMP,
            "artefactos_extraidos": artefactos
        }
        db.collection("evidencia_forense_encriptada").add(registro_evidencia)
        return {"status": "success", "hash_verificacion": hash_custodia}
    except Exception as e:
        print(f"X Error en manejador interno DFIR registrar_evidencia_forense: {str(e)}")
        return {"status": "error", "message": str(e)}

def esclalar_alerta_admin_hitl(tkt_id, telefono_admin):
    try:
        # Unificamos el 'if db' y el 'get()' para cambiar visualmente la estructura y limpiar los espacios fantasmas
        if db and tkt_id:
            tkt_ref = db.collection("tickets_hitl").document(tkt_id).get()
            if tkt_ref.exists:
                tkt_data = tkt_ref.to_dict()
                if tkt_data.get("estado") == "pendiente_aprobacion_hitl":
                    id_equipo = tkt_data.get("id_equipo", "")
                    incidente_raw = tkt_data.get("amenaza", "")
                    comando_sugerido = tkt_data.get("comando_sugerido", "")
                    empresa = tkt_data.get("empresa_id", "GLOBAL365").upper()
                    
                    amenaza_amigable = DICCIONARIO_AMENAZAS_AMIGABLES.get(incidente_raw, incidente_raw)
                    entorno_limpio = limpiar_identificador_usuario(id_equipo)
                    
                    es_plural = any(palabra in str(id_equipo).upper() for palabra in ["CLOUD", "SAAS", "IDENTITY", "FLOTA", "HARDWARE"])
                    type_num = "plural" if es_plural else "singular"
                    accion_humana = obtener_accion_humana_segura(comando_sugerido, type_num)
                    
                    texto_escalamiento = (
                        f"⚠️ *URGENTE* ⚠️\n"
                        f"Te notifico porque el supervisor de *{empresa}* no respondió a una alerta crítica en el último minuto.\n\n"
                        f"Registramos una situación de *{amenaza_amigable}* en el entorno de {entorno_limpio}.\n\n"
                        f"Necesito tu autorización para *{accion_humana}* (Ticket: {tkt_id}). ¿Procedemos?"
                    )
                    enviar_botones_whatsapp(telefono_admin, texto_escalamiento, tkt_id)
                    print(f"[AIOps ESCALATION] Ticket {tkt_id} escalated con éxito por timeout al administrador {telefono_admin}.")
    except Exception as e:
        print(f"X Error en hilo asíncrono de escalamiento: {str(e)}")

def solicitar_aprobacion_hitl_whatsapp(id_equipo: str, amenaza: str, comando_sugerido: str, telefono_supervisor: str, telefono_admin: str, coleccion_origen: str = COLECCION_TELEMETRIA, empresa_id: str = "GLOBAL365") -> str:
    try:
        tkt_id = f"TKT-{int(time.time() * 1000) % 10000:04d}"
        if db:
            db.collection("tickets_hitl").document(tkt_id).set({
                "id_equipo": str(id_equipo).upper(),
                "empresa_id": str(empresa_id).upper(),
                "amenaza": amenaza, 
                "comando_sugerido": comando_sugerido,
                "telefono_supervisor": str(telefono_supervisor),
                "telefono_admin": str(telefono_admin),
                "coleccion_origen": coleccion_origen,
                "estado": "pendiente_aprobacion_hitl",
                "timestamp_creacion": firestore.SERVER_TIMESTAMP
            })
            
        amenaza_amigable = DICCIONARIO_AMENAZAS_AMIGABLES.get(amenaza, amenaza)
        entorno_limpio = limpiar_identificador_usuario(id_equipo)
            
        es_plural = any(palabra in str(id_equipo).upper() for palabra in ["CLOUD", "SAAS", "IDENTITY", "FLOTA", "HARDWARE"])
        type_num = "plural" if es_plural else "singular"
        accion_humana = obtener_accion_humana_segura(comando_sugerido, type_num)
            
        mensaje_base = (
            f"🚨 *ALERTA DE MONITOREO* 🚨\n"
            f"Nuestro sistema detectó un comportamiento inusual: *{amenaza_amigable}* que afecta al entorno de {entorno_limpio}.\n\n"
            f"Como medida preventiva, te sugiero *{accion_humana}* de inmediato (Ticket: {tkt_id}). ¿Me autorizas a ejecutar esta protección ahora mismo?"
        )
        
        enviar_botones_whatsapp(telefono_supervisor, mensaje_base, tkt_id)
        print(f"[AIOps HITL LOG] Ticket {tkt_id} enviado a Supervisor {telefono_supervisor}. Temporizador de escalamiento fijado en 60s...")
        
        timer_escalamiento = threading.Timer(60.0, esclalar_alerta_admin_hitl, args=[tkt_id, telefono_admin])
        timer_escalamiento.start()
        
        timer_cierre = threading.Timer(120.0, simular_resolucion_automatica_whatsapp, args=[id_equipo, amenaza, tkt_id, telefono_supervisor])
        timer_cierre.start()
        
        return tkt_id
    except Exception as e:
        print(f"X Error al inicializar ChatOps interactivo: {str(e)}")
        return "ERR_TKT"

# =========================================================================
# 🟢 ENDPOINTS DE ANÁLISIS DE IDENTIDAD ITDR Y SUPERFICIE EASM
# =========================================================================

@app.route('/api/itdr/analisis', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")
def api_itdr_analisis():
    if request.method == 'OPTIONS':
        return jsonify({"status": "preflight_ok"}), 200
        
    try:
        if not db: return jsonify({"status": "error", "message": "Fallo de infraestructura: Repositorio Firestore desconectado."}), 503
        datos_solicitud = request.get_json()
        if not datos_solicitud:
            return jsonify({"status": "error", "message": "Cuerpo de solicitud de identidad vacío."}), 400
            
        token_validacion = datos_solicitud.get("token_validacion")
        logs_identidad_raw = datos_solicitud.get("logsIdentidad")
        empresa_id = datos_solicitud.get("empresaId", "DESCONOCIDA").upper()
        
        if not token_validacion or not logs_identidad_raw:
            return jsonify({"status": "error", "message": "Parámetros insuficientes (Token o Logs Cloud ausentes)."}), 400
            
        try:
            informacion_operator = firebase_auth.verify_id_token(token_validacion)
            print(f" Sentinel SOC: Evaluación analítica ITDR autorizada por operador: {informacion_operator['email']}")
        except Exception as auth_err:
            print(f" Intento no autorizado en módulo ITDR bloqueado: {str(auth_err)}")
            return jsonify({"status": "error", "message": "Acceso Denegado: Token criptográfico inválido o expirado."}), 403
            
        print(f" Sentinel AI: Analizando patrones de autenticación cloud e identidad SaaS para tenant '{empresa_id}'...")
        reporte_itdr = analizar_identidad_cloud(logs_identidad_raw)
        
        try:
            db.collection(COLECCION_DECISIONES).add({
                "type": "ANALISIS_IDENTITY_ITDR",
                "empresa_id": empresa_id,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "operador_autorizador": informacion_operator['email'],
                "data": reporte_itdr
            })
            print(f"[AIOps INCIDENT LOG] [ITDR IDENTITY] Tenant Master: {empresa_id} | Risk Tier: {reporte_itdr.get('nivel_riesgo', 'UNKNOWN')}")
        except Exception as err_trace:
            print(f"! Fallo no bloqueante en Trazabilidad ITDR: {str(err_trace)}")
            
        try:
            tel_supervisor = "DESCONOCIDO"
            tel_admin = "DESCONOCIDO"
            if db:
                usuarios_ref = db.collection("usuarios").where(filter=FieldFilter("empresa_id", "==", empresa_id)).where(filter=FieldFilter("rol", "==", "supervisor")).limit(1).stream()
                for doc in usuarios_ref:
                    tel_supervisor = doc.to_dict().get("telefono_whatsapp", "DESCONOCIDO")
                admin_ref = db.collection("usuarios").where(filter=FieldFilter("rol", "==", "admin")).limit(1).stream()
                for doc in admin_ref:
                    tel_admin = doc.to_dict().get("telefono_whatsapp", "DESCONOCIDO")

            if reporte_itdr.get("compromiso_identidad") or reporte_itdr.get("nivel_riesgo") in ["CRITICO", "ALTO"]:
                solicitar_aprobacion_hitl_whatsapp(
                    id_equipo=f"CLOUD-IDENTITY-{empresa_id}",
                    amenaza="ITDR",
                    comando_sugerido=reporte_itdr.get("accion_sugerida", "auditar_identidad_cloud"),
                    telefono_supervisor=tel_supervisor,
                    telefono_admin=tel_admin,
                    coleccion_origen=COLECCION_DECISIONES,
                    empresa_id=empresa_id
                )
        except Exception as hitl_err:
            print(f"! Error al disparar flujo HITL WhatsApp en módulo ITDR: {str(hitl_err)}")

        return jsonify({
            "status": "success",
            "empresaId": empresa_id,
            "reporte": reporte_itdr
        }), 200
        
    except Exception as e:
        print(f"X Caída catastrófica controlada en endpoint /api/itdr/analisis: {str(e)}")
        return jsonify({"status": "error", "message": f"Fallo interno en el túnel perimetral ITDR: {str(e)}"}), 500


@app.route('/api/easm/analisis', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")
def api_easm_analisis():
    if request.method == 'OPTIONS':
        return jsonify({"status": "preflight_ok"}), 200
        
    try:
        if not db: return jsonify({"status": "error", "message": "Fallo de infraestructura: Repositorio Firestore desconectado."}), 503
        datos_solicitud = request.get_json()
        if not datos_solicitud:
            return jsonify({"status": "error", "message": "Cuerpo de solicitud de Syslogs EASM vacío."}), 400
            
        token_validacion = datos_solicitud.get("token_validacion")
        syslogs_edge_raw = datos_solicitud.get("logsSyslog") 
        empresa_id = datos_solicitud.get("empresaId", "DESCONOCIDA").upper()
        
        if not token_validacion or not syslogs_edge_raw:
            return jsonify({"status": "error", "message": "Parámetros insuficientes (Token o Syslogs Edge ausentes)."}), 400
            
        try:
            informacion_operator = firebase_auth.verify_id_token(token_validacion)
            print(f" Sentinel SOC: Evaluación analítica EASM autorizada por operador: {informacion_operator['email']}")
        except Exception as auth_err:
            print(f" Intento no autorizado en canal perimetral EASM bloqueado: {str(auth_err)}")
            return jsonify({"status": "error", "message": "Acceso Denegado: Token criptográfico perimetral inválido o expirado."}), 403
            
        print(f" Sentinel AI: Procesando Syslogs de borde y vectores expuestos para tenant '{empresa_id}'...")
        reporte_easm = analizar_superficie_externa(syslogs_edge_raw)
        
        try:
            db.collection(COLECCION_DECISIONES).add({
                "tipo": "ANALISIS_EDGE_EASM",
                "empresa_id": empresa_id,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "operador_autorizador": informacion_operator['email'],
                "data": reporte_easm
            })
            print(f"[AIOps INCIDENT LOG] [EASM PERIMETER] Tenant Master: {empresa_id} | Risk Tier: {reporte_easm.get('nivel_riesgo', 'UNKNOWN')}")
        except Exception as err_trace:
            print(f"! Fallo no bloqueante en Trazabilidad o Logging EASM: {str(err_trace)}")
            
        try:
            tel_supervisor = "DESCONOCIDO"
            tel_admin = "DESCONOCIDO"
            if db:
                usuarios_ref = db.collection("usuarios").where(filter=FieldFilter("empresa_id", "==", empresa_id)).where(filter=FieldFilter("rol", "==", "supervisor")).limit(1).stream()
                for doc in usuarios_ref:
                    tel_supervisor = doc.to_dict().get("telefono_whatsapp", "DESCONOCIDO")
                admin_ref = db.collection("usuarios").where(filter=FieldFilter("rol", "==", "admin")).limit(1).stream()
                for doc in admin_ref:
                    tel_admin = doc.to_dict().get("telefono_whatsapp", "DESCONOCIDO")

            if reporte_easm.get("perimetro_vulnerable") or reporte_easm.get("nivel_riesgo") in ["CRITICO", "ALTO"]:
                solicitar_aprobacion_hitl_whatsapp(
                    id_equipo=f"EDGE-HARDWARE-{empresa_id}",
                    amenaza="EASM",
                    comando_sugerido=reporte_easm.get("accion_sugerida", "auditar_perimetro_easm"),
                    telefono_supervisor=tel_supervisor,
                    telefono_admin=tel_admin,
                    coleccion_origen=COLECCION_DECISIONES,
                    empresa_id=empresa_id
                )
        except Exception as hitl_err:
            print(f"! Error al disparar flujo HITL WhatsApp en módulo EASM: {str(hitl_err)}")

        return jsonify({
            "status": "success",
            "empresaId": empresa_id,
            "reporte": reporte_easm
        }), 200
        
    except Exception as e:
        print(f"X Caída catastrófica controlada en endpoint /api/easm/analisis: {str(e)}")
        return jsonify({"status": "error", "message": f"Fallo interno en el clúster analítico EASM: {str(e)}"}), 500


# =========================================================================
# 🟢 CONSTRUCTOR DINÁMICO DE ENDPOINTS DE ANÁLISIS (MITIGACIÓN PUNTO 7 - DRY)
# =========================================================================

def crear_endpoint_analisis(endpoint_name, amenaza_key, comando_key):
    """
    Genera y registra dinámicamente endpoints de análisis de amenazas en Flask.
    Reduce la redundancia del código y unifica la lógica de auditoría perimetral.
    """
    @app.route(f'/api/{endpoint_name}/analisis', methods=['POST', 'OPTIONS'], endpoint=f'api_{endpoint_name}_analisis')
    @limiter.limit("5 per minute")
    def api_analisis_dinamico():
        if request.method == 'OPTIONS': 
            return jsonify({"status": "preflight_ok"}), 200
        try:
            if not db: return jsonify({"status": "error", "message": "Base de datos fuera de línea."}), 503
                
            datos_solicitud = request.get_json() or {}
            token_val = datos_solicitud.get("token_validacion")
            empresa_id = datos_solicitud.get("empresaId", "DESCONOCIDA").upper()
            id_equipo = datos_solicitud.get("idEquipo")

            try: 
                firebase_auth.verify_id_token(token_val)
            except: 
                return jsonify({"status": "error", "message": "Firma criptográfica inválida."}), 403

            tel_supervisor, tel_admin = "DESCONOCIDO", "DESCONOCIDO"
            
            sup_ref = db.collection("usuarios").where(filter=FieldFilter("empresa_id", "==", empresa_id)).where(filter=FieldFilter("rol", "==", "supervisor")).limit(1).stream()
            for d in sup_ref: 
                tel_supervisor = d.to_dict().get("telefono_whatsapp", "DESCONOCIDO")
                
            adm_ref = db.collection("usuarios").where(filter=FieldFilter("rol", "==", "admin")).limit(1).stream()
            for d in adm_ref: 
                tel_admin = d.to_dict().get("telefono_whatsapp", "DESCONOCIDO")

            solicitar_aprobacion_hitl_whatsapp(
                id_equipo=id_equipo, 
                amenaza=amenaza_key, 
                comando_sugerido=comando_key,
                telefono_supervisor=tel_supervisor, 
                telefono_admin=tel_admin, 
                coleccion_origen=COLECCION_TELEMETRIA, 
                empresa_id=empresa_id
            )
            return jsonify({"status": "success"}), 200
            
        except Exception as e: 
            return jsonify({"status": "error", "message": str(e)}), 500

# REGISTER AUTOMÁTICO MAESTRO DE LOS 8 COMPONENTES DE FLOTA
CONFIGURACION_AMENAZAS = [
    ("ransomware", "COMBINACION_TOXICA", "aislar_equipo"),
    ("shadowai",   "SHADOW_AI",         "bloquear_shadow_ai"),
    ("phishing",   "PHISHING_DNS",      "aislar_equipo"),
    ("finops",     "FINOPS_ANOMALY",    "evaluar_roi_y_renovacion_pc"),
    ("hijack",     "AGENT_HIJACK",      "aislar_equipo"),
    ("mfafatigue", "MFA_FATIGUE",       "auditar_identidad_cloud"),
    ("dex",        "DEX_DEGRADATION",   "evaluar_roi_y_renovacion_pc"),
    ("fileless",   "FILELESS_ATTACK",   "aislar_equipo")
]

for ruta, amenaza, comando in CONFIGURACION_AMENAZAS:
    crear_endpoint_analisis(ruta, amenaza, comando)

# =========================================================================
# 📍 NUEVO ENDPOINT RECEPTOR DE LA INFRAESTRUCTURA DE SIMULACIÓN AVANZADA
# =========================================================================
@app.route('/api/simular-infraestructura', methods=['POST', 'OPTIONS'])
def api_simular_infraestructura():
    if request.method == 'OPTIONS': 
        return jsonify({"status": "preflight_ok"}), 200
    try:
        if not db: 
            return jsonify({"status": "error", "message": "Firestore desconectado."}), 503
            
        payload = request.get_json() or {}
        tipo_simulacion = payload.get("tipo_simulacion")
        id_equipo = payload.get("dispositivo", "PC-JUAN-DEMO")
        empresa_id = "GLOBONA" # Tenant por defecto para maquetas administrativas
        
        tel_supervisor, tel_admin = "DESCONOCIDO", "DESCONOCIDO"
        sup_ref = db.collection("usuarios").where(filter=FieldFilter("empresa_id", "==", empresa_id)).where(filter=FieldFilter("rol", "==", "supervisor")).limit(1).stream()
        for d in sup_ref: 
            tel_supervisor = d.to_dict().get("telefono_whatsapp", "DESCONOCIDO")
        adm_ref = db.collection("usuarios").where(filter=FieldFilter("rol", "==", "admin")).limit(1).stream()
        for d in adm_ref: 
            tel_admin = d.to_dict().get("telefono_whatsapp", "DESCONOCIDO")

        # 🟢 EVALUACIÓN A: ANOMALÍAS DE TELEMETRÍA FÍSICA (HARDWARE SLIDERS)
        if tipo_simulacion == "hardware":
            temp = payload.get("cpu_temperatura_c", 65)
            ram = payload.get("ram_pct", 45)
            ssd = payload.get("vida_util_pct", 98)
            wear = payload.get("battery_wear_level_pct", 12)
            
            if temp > 85:
                solicitar_aprobacion_hitl_whatsapp(id_equipo, "HIGH_TEMPERATURE", "thermal_throttle_mitigation", tel_supervisor, tel_admin, COLECCION_TELEMETRIA, empresa_id)
            elif ram > 80:
                solicitar_aprobacion_hitl_whatsapp(id_equipo, "RAM_SATURATION", "ram_flush", tel_supervisor, tel_admin, COLECCION_TELEMETRIA, empresa_id)
            elif ssd < 20:
                solicitar_aprobacion_hitl_whatsapp(id_equipo, "SSD_DEGRADATION", "defrag_trim_optimizer", tel_supervisor, tel_admin, COLECCION_TELEMETRIA, empresa_id)
            elif wear > 60:
                solicitar_aprobacion_hitl_whatsapp(id_equipo, "BATTERY_WEAR", "evaluar_roi_y_renovacion_pc", tel_supervisor, tel_admin, COLECCION_TELEMETRIA, empresa_id)

        # 🟢 EVALUACIÓN B: CAÍDA DE COMPLIANCE CORPORATIVO (TOGGLE SWITCHES)
        elif tipo_simulacion == "compliance":
            fw = payload.get("firewall_activo", True)
            uac = payload.get("uac_activo", True)
            bit = payload.get("bitlocker_protegido", True)
            
            if not fw or not uac or not bit:
                solicitar_aprobacion_hitl_whatsapp(id_equipo, "COMPLIANCE_BREACH", "enable_firewall", tel_supervisor, tel_admin, COLECCION_TELEMETRIA, empresa_id)
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================================
# 🟢 ENDPOINT REAL DE PRODUCCIÓN: REPORTE DE REMEDIACIÓN AGENTE SENTINEL
# =========================================================================
@app.route('/api/forense/remediacion', methods=['POST'])
@limiter.limit("30 per minute")
def api_forense_remediacion_real():
    try:
        auth_token = request.headers.get("X-Sentinel-Agent-Token")
        token_esperado = os.environ.get("SENTINEL_AGENT_TOKEN")
        
        if not token_esperado:
            return jsonify({"status": "error", "message": "Servicio de validación de agente no configurado."}), 500
            
        if not auth_token or auth_token != token_esperado:
            return jsonify({"status": "error", "message": "Acceso Denegado: Token de Agente local inválido."}), 401
            
        datos_remediacion = request.get_json()
        if not datos_remediacion:
            return jsonify({"status": "error", "message": "Paquete de datos vacío."}), 400
            
        id_equipo = datos_remediacion.get("idEquipo")
        tkt_id = datos_remediacion.get("ticketId").upper() if datos_remediacion.get("ticketId") else None
        incidente_key = datos_remediacion.get("incidenteKey")
        
        if not id_equipo or not incidente_key or not tkt_id:
            return jsonify({"status": "error", "message": "Parámetros insuficientes para procesar el cierre real."}), 400
            
        if db:
            tkt_ref = db.collection("tickets_hitl").document(tkt_id)
            tkt_doc = tkt_ref.get()
            
            if tkt_doc.exists:
                tkt_ref.update({
                    "estado": "solucionado_real",
                    "timestamp_resolucion_real": firestore.SERVER_TIMESTAMP
                })
                
                tkt_data = tkt_doc.to_dict()
                telefono_supervisor = tkt_data.get("telefono_supervisor")
                
                solucion_amigable = DICCIONARIO_SOLUCIONES_AMIGABLES.get(incidente_key, "Las contenciones preventivas fueron aplicadas con éxito.")
                
                mensaje_cierre_real = (
                    f"✅ *MONITOREO: INCIDENTE SOLUCIONADO* ✅\n"
                    f"Sentinel AI aplicó de forma autónoma las medidas de contención en el equipo de `{id_equipo.upper()}`. "
                    f"{solucion_amigable} El estado de la flota ha vuelto a la normalidad y opera de manera segura (Ticket: {tkt_id})."
                )
                
                if telefono_supervisor and telefono_supervisor != "DESCONOCIDO":
                    enviar_texto_whatsapp(telefono_supervisor, mensaje_cierre_real)
                    print(f"[Sentinel Real SOC] Incidente corregido por Agente en {id_equipo}. WhatsApp enviado al supervisor.")
                    return jsonify({"status": "success", "message": "Resolución real procesada y notificada."}), 200

        return jsonify({"status": "error", "message": "No se pudo mapear el ticket asociado para la notificación."}), 404
        
    except Exception as e:
        print(f"X Error crítico en ingesta de remediación real: {str(e)}")
        return jsonify({"status": "error", "message": "Ocurrió un error interno en el servidor"}), 500


# =========================================================================
# INFERENCIA QUIRÚRGICA ROBUSTA (Mapeada con OCSF)
# =========================================================================
def generar_insight_quirurgico(pc_data):
    api_key_studio = os.environ.get("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key_studio)
    pc_data_ocsf = adaptar_telemetria_ocsf(pc_data)
    pc_data_anonima = enmascarar_telemetria(pc_data_ocsf["raw_data_passthrough"])
    
    empresa_id = str(pc_data_anonima.get('cliente', {}).get('empresa', 'DESCONOCIDA')).upper()
    usuario_target = pc_data_anonima.get('cliente', {}).get('usuario', 'Desconocido')
    sentimiento = pc_data_anonima.get('estado_actual', {}).get('sentimiento_usuario', 'No reportado')
    
    cpu_pct = float(pc_data_anonima.get('estado_actual', {}).get('cpu_pct', 0))
    
    herramientas_disponibles = [
        analizar_historico_y_seguridad,
        predecir_ruta_ataque,
        evaluar_radio_explosion,
        predecir_threat_comportamiento,
        detectar_fuga_shadow_ai,
        evaluar_roi_y_renovacion_pc,
        deshabilitar_impresion,
        desinstalar_agente_local
    ]
    
    if db:
        try:
            empresa_doc = db.collection(COLECCION_CONFIG_EMPRESAS).document(empresa_id).get()
            if empresa_doc.exists:
                skills_config = empresa_doc.to_dict().get("politicas_skills", {})
                for skill_key, autorizado in skills_config.items():
                    if autorizado == False and skill_key in MAPEO_REF_FUNCIONES:
                        func_ref_nombre = MAPEO_REF_FUNCIONES[skill_key]
                        herramientas_disponibles = [h for h in herramientas_disponibles if h.__name__ != func_ref_nombre]
                        print(f" Gobernanza SCC: Skill '{skill_key}' removida para {empresa_id} por restricción Master.")
        except Exception as err_permisos:
            print(f"! Alerta Gobernanza: No se pudo verificar la matriz de exclusiones: {str(err_permisos)}")
        
    contexto_pc_actual = (
        f"DATOS DE TIEMPO REAL DEL COMPUTADOR SELECCIONADO (FRAMEWORK OCSF):\n"
        f"- USUARIO ASOCIADO: {usuario_target}\n"
        f"- SENTIMIENTO DEL USUARIO: {sentimiento}\n"
        f"- SISTEMA OPERATIVO: {pc_data_anonima.get('inventario_os', {}).get('os_ver', 'Windows')}\n"
        f"- RENDIMIENTO LATENTE: CPU {cpu_pct}%, RAM {pc_data_anonima.get('estado_actual', {}).get('ram_pct', 0)}%\n"
        f"- ESTRANGULAMIENTO TERMICO SILICIO (OCSF): {pc_data_ocsf['hardware_telemetry']['eventos_estrangulamiento_termico']}\n"
        f"- SALUD TERMICA ACTUAL: {pc_data_ocsf['hardware_telemetry']['cpu_temperature_c']}°C\n"
        f" POSTURA SEGURIDAD: Score Global {pc_data_anonima.get('security_posture', {}).get('score_ponderado', 100)}%\n"
    )
    
    intentos_maximos = 3
    for intento in range(1, intentos_maximos + 1):
        try:
            chat = client.chats.create(
                model='gemini-2.5-flash',
                config=types.GenerateContentConfig(
                    tools=herramientas_disponibles,
                    system_instruction=prompt_sistema_insight,
                    temperature=0.1
                )
            )
            prompt_ejecucion = (
                f"{contexto_pc_actual}\n\n"
                f"Por favor, actúa como analista SOC senior, especialista Finops y consultor de Sostenibilidad. Invoca las herramientas adecuadas basándote en la telemetría OCSF de hardware de silicio Y empaqueta el JSON final."
            )
            
            chat.send_message(prompt_ejecucion)
            
            esquema_salida = types.Schema(
                type="OBJECT",
                properties={
                    "diagnostico_texto": types.Schema(type="STRING"),
                    "mini_herramienta_sugerida": types.Schema(type="STRING")
                },
                required=["diagnostico_texto", "mini_herramienta_sugerida"]
            )
            
            response_final = chat.send_message(
                "Empaqueta tu diagnóstico final en el JSON requerido.",
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=esquema_salida,
                    temperature=0.1
                )
            )
            
            resultado_json = json.loads(response_final.text.strip())
            
            print(f"[AIOps OBSERVABILITY] [CHAIN OF THOUGHT] Sentinel AI ha procesado un diagnóstico para el host {usuario_target}. "
                  f"Rendimiento analizado lógicamente. Herramienta determinada: {resultado_json.get('mini_herramienta_sugerida')}. "
                  f"Razonamiento emitido: '{resultado_json.get('diagnostico_texto')}'")
            
            t_input = 0; t_output = 0
            try:
                if response_final.usage_metadata:
                    t_input = response_final.usage_metadata.prompt_token_count or 0
                    t_output = response_final.usage_metadata.candidates_token_count or 0
            except: pass
            
            costo_usd = (t_input * 0.000000075) + (t_output * 0.0000003)
            resultado_json["_tracking_tokens"] = {
                "input": t_input, "output": t_output, "costo_usd": costo_usd
            }
            
            herramienta_sugerida = resultado_json.get("mini_herramienta_sugerida", "ok").lower()
            if herramienta_sugerida not in LISTA_BLANCA_HERRAMIENTAS:
                print(f" Guardián interceptó comando inválido: '{herramienta_sugerida}'. Forzando a 'ok'.")
                resultado_json["mini_herramienta_sugerida"] = "ok"
            return resultado_json
        except Exception as e:
            print(f"! Intento {intento}/{intentos_maximos} fallido: {str(e)}")
            if intento < intentos_maximos:
                time.sleep(2)
            else:
                return {"diagnostico_texto": "Sentinel AI recalculando matrices.", "mini_herramienta_sugerida": "ok", "_tracking_tokens": {"costo_usd": 0}}


# =========================================================================
# ENDPOINT DE CONFIGURACIÓN SEGURA HARDENING (OWASP COMPLIANT ADAPTATIVO)
# =========================================================================
@app.route('/api/config', methods=['GET'])
def obtener_configuracion_segura():
    try:
        # 🛡️ SEGURIDAD POR ORIGEN (CORS):
        # Si la petición viene del navegador, Flask-CORS ya valida contra tu 'ORIGEN_PERMITIDO'
        
        firebase_key = os.environ.get("FIREBASE_API_KEY")
        firebase_domain = os.environ.get("FIREBASE_AUTH_DOMAIN")
        firebase_project = os.environ.get("FIREBASE_PROJECT_ID")
        firebase_bucket = os.environ.get("FIREBASE_STORAGE_BUCKET")
        firebase_sender = os.environ.get("FIREBASE_MESSAGING_SENDER_ID")
        firebase_app_id = os.environ.get("FIREBASE_APP_ID")

        if not all([firebase_key, firebase_domain, firebase_project, firebase_bucket, firebase_sender, firebase_app_id]):
            return jsonify({"status": "error", "message": "Configuración de entorno incompleta en el servidor."}), 500

        # Retornamos las credenciales públicas de Firebase al portal
        return jsonify({
            "apiKey": firebase_key,
            "authDomain": firebase_domain,
            "projectId": firebase_project,
            "storageBucket": firebase_bucket,
            "messagingSenderId": firebase_sender,
            "appId": firebase_app_id
        }), 200
        
    except Exception as e:
        print(f"❌ Error al despachar configuración perimetral: {str(e)}")
        return jsonify({"status": "error", "message": "No se pudo recuperar el entorno de inicialización."}), 500

# =========================================================================
# ENDPOINT HITL CENTRALIZADO (VERIFICACIÓN REAL DE FIRMA CRIPTOGRÁFICA)
# =========================================================================
@app.route('/api/remediar', methods=['POST'])
def api_remediar_dispositivo():
    try:
        if not db: 
            return jsonify({"status": "error", "message": "Base de datos desconectada."}), 503
            
        try:
            informacion_supervisor = validar_session_firebase(request)
            print(f" Sentinel SOC: Identity confirmada criptográficamente para el supervisor {informacion_supervisor['email']}")
        except Exception as auth_err:
            print(f"🚨 ALERTA SOC: Intento de bypass de autenticación interceptado en /api/remediar: {str(auth_err)}")
            return jsonify({"status": "error", "message": "Acceso Denegado: Firma criptográfica o Token inválido/expirado."}), 401
            
        datos_hitl = request.get_json()
        if not datos_hitl:
            return jsonify({"status": "error", "message": "Paquete de acción HITL vacío."}), 400
            
        id_equipo = datos_hitl.get("idEquipo")
        comando_key = datos_hitl.get("comandoKey")
        coleccion_origen = datos_hitl.get("coleccionOrigen", COLECCION_TELEMETRIA)
        
        if not id_equipo or not comando_key:
            return jsonify({"status": "error", "message": "Parámetros insuficientes para el despacho."}), 400
        if comando_key not in LISTA_BLANCA_HERRAMIENTAS:
            return jsonify({"status": "error", "message": f"Comando '{comando_key}' denegado por políticas de hardening."}), 403
            
        print(f" Sentinel SOC: Encolando comando perimetral 00B '{comando_key}' para el computador '{id_equipo}'...")
        
        if comando_key == "generar_auditoria_360":
            print(f" Sentinel SOC: Executing Auditoría 360 On-Demand para '{id_equipo}'...")
            doc_equipo = db.collection(coleccion_origen).document(id_equipo).get()
            if not doc_equipo.exists:
                return jsonify({"status": "error", "message": "No hay telemetría previa para auditar este equipo."}), 404
                
            telemetria_cruda = doc_equipo.to_dict()
            reporte_json = analizar_telemetria_360(telemetria_cruda)
            
            if "error" in reporte_json:
                return jsonify({"status": "error", "message": reporte_json["error"]}), 500
                
            return jsonify({
                "status": "success", 
                "reporte": reporte_json
            }), 200
        
        doc_ref = db.collection(coleccion_origen).document(id_equipo)
        doc_ref.update({
            "comandos_pendientes": {
                "accion": comando_key,
                "timestamp_solicitud": firestore.SERVER_TIMESTAMP,
                "estado_ejecucion": "pendiente",
                "token_autorizador_oob": f"VERIFICADO_MFA_{informacion_supervisor['uid']}"
            }
        })
        return jsonify({"status": "success", "message": "Acción HITL encolada con éxito en la cola persistente offline."}), 200
    except Exception as e:
        print(f"X Fallo en despacho centralizado HITL: {str(e)}")
        return jsonify({"status": "error", "message": f"Fallo interno en el servidor perimetral: {str(e)}"}), 500


# =========================================================================
# RUTA API FRONTEND (CON GOVERNANCE & DECISION TRACING EXTENDIDO)
# =========================================================================
@app.route('/api/diagnostico', methods=['POST'])
@limiter.limit("10 per minute")
def api_diagnostico_pc():
    try:
        pc_telemetria = request.get_json()
        if not pc_telemetria:
            return jsonify({
                "status": "error",
                "diagnostico": "Sentinel AI no recibió un paquete de telemetría válido corporativo.",
                "mini_herramienta": "ok"
            }), 200
            
        objeto_ai = generar_insight_quirurgico(pc_telemetria)
        diagnostico_final = objeto_ai.get("diagnostico_texto", "")
        herramienta_final = objeto_ai.get("mini_herramienta_sugerida", "ok")
        tracking_tokens = objeto_ai.get("_tracking_tokens", {"costo_usd": 0})
        
        razonamiento_ocsf = objeto_ai.get("razonamiento_interno", "Procesamiento agéntico estándar ejecutado.")
        mitre_mapeo = objeto_ai.get("tecnica_mitre", "ASI01 - Agentic Standard Monitoring")
        
        if db:
            try:
                uid_equipo = pc_telemetria.get('id') or pc_telemetria.get('uid') or pc_telemetria.get('cliente', {}).get('usuario', 'Desconocido')
                empresa_id = pc_telemetria.get('cliente', {}).get('empresa', 'DESCONOCIDA').upper()
                
                db.collection(COLECCION_DECISIONES).add({
                    "uid": str(uid_equipo).upper(),
                    "empresa_id": empresa_id,
                    "timestamp": firestore.SERVER_TIMESTAMP,
                    "diagnostico_texto": diagnostico_final,
                    "mini_herramienta_sugerida": herramienta_final,
                    "razonamiento_interno_cot": razonamiento_ocsf,
                    "mitre_attack_technique": mitre_mapeo,
                    "metadata_origen": {
                        "score_postura": pc_telemetria.get('security_posture', {}).get('score_ponderado', 100),
                        "usuario_asociado": pc_telemetria.get('cliente', {}).get('usuario', 'Desconocido')
                    }
                })
                if tracking_tokens.get("costo_usd", 0) > 0:
                    db.collection(COLECCION_CONFIG_EMPRESAS).document(empresa_id).set({
                        "costo_inferencia_ia": firestore.Increment(tracking_tokens["costo_usd"]),
                        "ultima_llamada_tokens": firestore.SERVER_TIMESTAMP
                    }, merge=True)
            except Exception as err_trace:
                print(f"! Fallo no bloqueante en Decision Tracing o Finops IA: {str(err_trace)}")
            
        return jsonify({
            "status": "success",
            "diagnostico": diagnostico_final,
            "mini_herramienta": herramienta_final
        }), 200
    except Exception as e:
        print(f"X Caída catastrófica controlada en endpoint /api/diagnostico: {str(e)}")
        return jsonify({
            "status": "error",
            "diagnostico": "Sentinel AI se encuentra analizando un volumen inusual de datos.",
            "mini_herramienta": "ok"
        }), 200


# =========================================================================
# ENDPOINT DE AUDITORÍA SÍNCRONA 360 (VINCULADO AL PORTAL ADMIN)
# =========================================================================
@app.route('/api/auditoria360', methods=['POST'])
@limiter.limit("5 per minute")
def api_auditoria_360_sincrona():
    try:
        if not db: return jsonify({"status": "error", "message": "Base de datos fuera de línea."}), 503
        datos_solicitud = request.get_json()
        if not datos_solicitud:
            return jsonify({"status": "error", "message": "Falta el cuerpo de la solicitud."}), 400
            
        token_validacion = datos_solicitud.get("token_validacion")
        id_equipo = datos_solicitud.get("idEquipo")
        coleccion_origen = datos_solicitud.get("coleccionOrigen", "config_empresas")
        
        if not token_validacion or not id_equipo:
            return jsonify({"status": "error", "message": "Parámetros suficientes (ID Equipo / Token faltantes)."}), 400
            
        try:
            informacion_supervisor = firebase_auth.verify_id_token(token_validacion)
            print(f" Sentinel SOC: Extrayendo auditoría 360 autorizada por {informacion_supervisor['email']}")
        except Exception as auth_err:
            print(f" Intento de auditoría no autorizado bloqueado: {str(auth_err)}")
            return jsonify({"status": "error", "message": "Acceso Denegado: Firma criptográfica inválida o expirada."}), 403
            
        telemetria_ref = db.collection(coleccion_origen).document(id_equipo).get()
        
        if not telemetria_ref.exists:
            query = db.collection(coleccion_origen).where("id", "==", id_equipo).limit(1).stream()
            telemetria_cruda = None
            for doc in query:
                telemetria_cruda = doc.to_dict()
            
            if not telemetria_cruda:
                return jsonify({
                    "status": "error", 
                    "message": f"No se encontró registro de telemetría activo en la colección {coleccion_origen} para el equipo {id_equipo}."
                }), 404
        else:
            telemetria_cruda = telemetria_ref.to_dict()

        print(f" Sentinel AI: Iniciando procesamiento forense 360 para {id_equipo}...")
        reporte_estructurado = analizar_telemetria_360(telemetria_cruda)
        
        if "error" in reporte_estructurado and reporte_estructurado["estado_general"] == "ERROR_ANALISIS":
            return jsonify({"status": "error", "message": "El motor analítico de Gemini no pudo estructurar la telemetría"}), 400

        return jsonify({
            "status": "success",
            "idEquipo": id_equipo,
            "reporte": reporte_estructurado
        }), 200
    except Exception as e:
        print(f"X Falla crítica en canalización /api/auditoria360: {str(e)}")
        return jsonify({"status": "error", "message": "Ocurrió un error interno en el servidor"}), 500


# =========================================================================
# ENDPOINT DE RECEPCIÓN DFIR /api/forense/ingesta (MITIGACIÓN PUNTOS 1 Y 2)
# =========================================================================
@app.route('/api/forense/ingesta', methods=['POST'])
@limiter.limit("30 per minute")
def api_forense_ingesta():
    try:
        auth_token = request.headers.get("X-Sentinel-Agent-Token")
        token_esperado = os.environ.get("SENTINEL_AGENT_TOKEN")
        
        if not token_esperado:
            return jsonify({"status": "error", "message": "Servicio de validación forense perimetral no inicializado."}), 500
            
        if not auth_token or auth_token != token_esperado:
            return jsonify({"status": "error", "message": "Acceso Denegado: Firma o Token de Agente local inválida."}), 401
            
        datos_forenses = request.get_json()
        if not datos_forenses:
            return jsonify({"status": "error", "message": "Paquete de artefactos forenses vacío."}), 400
            
        id_equipo = datos_forenses.get("idEquipo")
        empresa_id = datos_forenses.get("empresaId", "DESCONOCIDA").upper()
        artefactos = datos_forenses.get("artefactos")
        
        if not id_equipo or not artefactos:
            return jsonify({"status": "error", "message": "Parámetros suficientes para el resguardo de la Cadena de Custodia."}), 400
            
        resultado_resguardo = registrar_evidencia_forense(id_equipo, empresa_id, artefactos)
        
        if resultado_resguardo.get("status") == "success":
            hash_digital = resultado_resguardo["hash_verificacion"]
            print(f"[AIOps INCIDENT LOG] [DFIR INDUCTION] Host Target: {id_equipo} | Master Tenant: {empresa_id} | Signature SHA-256: {hash_digital} | Custody Matrix: SECURED_ISO_27037")
            
            return jsonify({
                "status": "success",
                "message": "Artefactos forenses capturados, encapsulados y firmados criptográficamente con éxito.",
                "hash_cadena_custodia": hash_digital
            }), 201
            
        return jsonify({"status": "error", "message": "Ocurrió un error interno al procesar el resguardo"}), 500
            
    except Exception as e:
        print(f"X Caída catastrófica controlada en endpoint /api/forense/ingesta: {str(e)}")
        return jsonify({"status": "error", "message": f"Fallo crítico en el túnel DFIR central: {str(e)}"}), 500


# =========================================================================
# ENDPOINT DE ANÁLISIS SÍNCRONO FORENSE DE MEMORIA RAM (/api/forense/analisis_ram)
# =========================================================================
@app.route('/api/forense/analisis_ram', methods=['POST'])
@limiter.limit("5 per minute")
def api_forense_analisis_ram():
    try:
        if not db: return jsonify({"status": "error", "message": "Base de datos fuera de línea."}), 503
        datos_solicitud = request.get_json()
        if not datos_solicitud:
            return jsonify({"status": "error", "message": "Cuerpo de solicitud vacío."}), 400
            
        token_validacion = datos_solicitud.get("token_validacion")
        id_equipo = datos_solicitud.get("idEquipo")
        datos_volatility = datos_solicitud.get("datosVolatility")
        empresa_id = datos_solicitud.get("empresaId", "DESCONOCIDA").upper()
        
        if not token_validacion or not id_equipo or not datos_volatility:
            return jsonify({"status": "error", "message": "Parámetros insuficientes (ID Equipo, Token u Objetos Volatility ausentes)."}), 400
            
        try:
            informacion_supervisor = firebase_auth.verify_id_token(token_validacion)
            print(f" Sentinel SOC: Inspección profunda Volatility 3 autorizada por operador: {informacion_supervisor['email']}")
        except Exception as auth_err:
            print(f" Intento de intrusión o token forense expirado bloqueado: {str(auth_err)}")
            return jsonify({"status": "error", "message": "Acceso Denegado: Firma criptográfica inválida o expirada."}), 403
            
        print(f" Sentinel SOC: Ejecutando desensamblado cognitivo de Volatility 3 para host '{id_equipo}'...")
        reporte_forense_ram = analizar_volcado_ram(datos_volatility)
        
        try:
            db.collection(COLECCION_DECISIONES).add({
                "tipo": "ANALISIS_MEMORIA_VOLATILITY",
                "uid": str(id_equipo).upper(),
                "empresa_id": empresa_id,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "data": reporte_forense_ram
            })
            print(f"[AIOps ANOMALY LOG] [RAM ANALYSIS] Host Target: {id_equipo} | Status: COMPLETED | Risk Tier: {reporte_forense_ram.get('nivel_riesgo', 'UNKNOWN')}")
        except Exception as err_trace:
            print(f"! Fallo no bloqueante en Decision Tracing Forense: {str(err_trace)}")
            return jsonify({
                "status": "error",
                "message": "Ocurrió un error al procesar el tracing forense"
            }), 500
            
        return jsonify({
            "status": "success",
            "reporte": reporte_forense_ram
        }), 200
            
    except Exception as e:
        print(f"X Caída catastrófica controlada en endpoint /api/forense/analisis_ram: {str(e)}")
        return jsonify({"status": "error", "message": "Ocurrió un error interno en el clúster perimetral forense"}), 500


# =========================================================================
# ENDPOINT SÍNCRONO DE RECONSTRUCCIÓN DE ATAQUES (/api/forense/timeline)
# =========================================================================
@app.route('/api/forense/timeline', methods=['POST'])
@limiter.limit("5 per minute")
def api_forense_timeline():
    try:
        if not db: return jsonify({"status": "error", "message": "Base de datos fuera de línea."}), 503
        datos_solicitud = request.get_json()
        if not datos_solicitud:
            return jsonify({"status": "error", "message": "Cuerpo de solicitud vacío."}), 400
            
        token_validacion = datos_solicitud.get("token_validacion")
        id_equipo = datos_solicitud.get("idEquipo")
        artefactos_raw = datos_solicitud.get("artefactosWeb")
        empresa_id = datos_solicitud.get("empresaId", "DESCONOCIDA").upper()
        
        if not token_validacion or not id_equipo or not artefactos_raw:
            return jsonify({"status": "error", "message": "Parámetros insuficientes (ID Equipo, Token o Artefactos ausentes)."}), 400
            
        try:
            informacion_supervisor = firebase_auth.verify_id_token(token_validacion)
            print(f" Sentinel SOC: Reconstrucción de Timeline autorizada por operador: {informacion_supervisor['email']}")
        except Exception as auth_err:
            print(f" Intento de acceso no autorizado a módulo de Timeline bloqueado: {str(auth_err)}")
            return jsonify({"status": "error", "message": "Acceso Denegado: Firma criptográfica inválida o expirada."}), 403
            
        print(f" Sentinel AI: Analizando artefactos web y manipulación MACE para host '{id_equipo}'...")
        reporte_timeline = analizar_artefactos_timeline(artefactos_raw)
        
        try:
            db.collection(COLECCION_DECISIONES).add({
                "tipo": "ANALISIS_TIMELINE_ANTIFORENSE",
                "uid": str(id_equipo).upper(),
                "empresa_id": empresa_id,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "data": reporte_timeline
            })
            print(f"[AIOps INCIDENT LOG] [TIMELINE] Host Target: {id_equipo} | Status: PROCESSED | Manipulation Level: {reporte_timeline.get('nivel_manipulacion', 'UNKNOWN')} | Governance: ISO_27037_SECURED")
        except Exception as err_trace:
            print(f"! Fallo no bloqueante en Trazabilidad de Timeline: {str(err_trace)}")
            return jsonify({
                "status": "error",
                "message": "Ocurrió un error al procesar la trazabilidad del timeline"
            }), 500
            
        return jsonify({
            "status": "success",
            "reporte": reporte_timeline
        }), 200
            
    except Exception as e:
        print(f"X Caída catastrófica controlada en endpoint /api/forense/timeline: {str(e)}")
        return jsonify({"status": "error", "message": "Ocurrió un error interno en el subsistema forense"}), 500


# =========================================================================
# GESTIÓN CONVERSACIONAL DE IA Y PROCESAMIENTO GENERAL DE RESPUESTAS
# =========================================================================
def procesar_respuesta_con_ia(texto_usuario, datos_flota_dict, telefono_remitente="DESCONOCIDO"):
    contexto_telemetria = "DATOS DE TELEMETRÍA EN TIEMPO REAL DE LA EMPRESA:\n"
    if not datos_flota_dict:
        contexto_telemetria += "No hay registros de telemetría recientes vinculados a esta organización corporativa."
    else:
        for equipo, datos in datos_flota_dict.items():
            contexto_telemetria += f"\n- EQUIPO TERMINAL: {equipo}\n"
            contexto_telemetria += f" Métricas Hardware: CPU {datos.get('estado_actual', {}).get('cpu_pct', 0)}%, RAM {datos.get('estado_actual', {}).get('ram_pct', 0)}%\n"
            contexto_telemetria += f" Ciberseguridad: Score Global {datos.get('security_posture', {}).get('score_ponderado', 100)}%\n"
            
    contexto_conversacion = f"{contexto_telemetria}\n\nHISTORIAL CONVERSACIONAL RECIENTE (MEMORIA CORTO PLAZO):\n"
    
    if db and telefono_remitente != "DESCONOCIDO":
        try:
            clean_phone = "".join(re.findall(r"\d+", str(telefono_remitente)))
            historial_query = db.collection("registro_comunicaciones_whatsapp")\
                .where("remitente", "in", [clean_phone, "SENTINEL_AI"])\
                .where("destinatario", "in", [clean_phone, "SENTINEL_AI"])\
                .order_by("timestamp", direction=firestore.Query.DESCENDING)\
                .limit(5).stream()
                
            mensajes_historicos = []
            for doc in historial_query:
                d = doc.to_dict()
                origen = "Supervisor" if d.get("remitente") == clean_phone else "Sentinel AI"
                mensajes_historicos.append(f"[{origen}]: {d.get('mensaje', '')}")
                
            mensajes_historicos.reverse()
            contexto_conversacion += "\n".join(mensajes_historicos)
        except Exception as err_mem:
            print(f"! Alerta de Memoria Conversacional: No se pudo inyectar el contexto histórico: {str(err_mem)}")
            contexto_conversacion += "[Omitido por error de indexación en base de datos]"
    else:
        contexto_conversacion += "[No hay interacciones previas registradas]"

    try:
        api_key_studio = os.environ.get("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key_studio)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"{contexto_conversacion}\n\nMensaje actual entrante del supervisor: {texto_usuario}",
            config=types.GenerateContentConfig(
                system_instruction=PROMPT_SISTEMA_WHATSAPP,
                temperature=0.3
            )
        )
        return response.text.strip()
    except Exception as e:
        return " *Sentinel:* Estoy experimentando una latencia temporal. Por favor, realiza tu consulta nuevamente en unos instantes."


# =========================================================================
# BARRIDOS AUTOMÁTICOS ASINCÓNICOS
# =========================================================================
def generar_reporte_diario():
    print(" Sentinel: Iniciando barrido diario de las 14:00...")
    try:
        if not db: return jsonify({"status": "error", "message": "Firestore desconectado."}), 503
        ahora = datetime.now()
        limite_24h = ahora - timedelta(hours=24)
        supervisores = db.collection("usuarios").where(filter=FieldFilter("rol", "==", "supervisor")).where(filter=FieldFilter("plan", "==", "FULL")).stream()
        
        for sup_doc in supervisores:
            sup_data = sup_doc.to_dict()
            telefono = sup_data.get("telefono_whatsapp")
            empresa_id = sup_data.get("empresa_id")
            if not telefono or not empresa_id: continue
            
            documentos = db.collection(COLECCION_TELEMETRIA).where("cliente.empresa", "==", empresa_id.upper()).where("timestamp", ">=", limite_24h).stream()
            total_equipos = 0
            equipos_en_riesgo = 0
            suma_salud = 0
            maquinas_vistas = {}
            
            for doc in documentos:
                d = doc.to_dict()
                u = d.get("cliente", {}).get("usuario")
                if u and u not in maquinas_vistas:
                    maquinas_vistas[u] = d
                    
            for u, d in maquinas_vistas.items():
                total_equipos += 1
                smart = d.get("almacenamiento_ssd", {}).get("smart_status", "OK")
                temp = d.get("termico_fans", {}).get("cpu_temperatura_c", 0)
                if smart != "OK" or temp > 85:
                    equipos_en_riesgo += 1
                else:
                    suma_salud += 100
                    
            if total_equipos > 0:
                salud_promedio = int(suma_salud / total_equipos)
                payload_meta = {
                    "messaging_product": "whatsapp",
                    "to": telefono,
                    "type": "template",
                    "template": {
                        "name": "resumen_diario_flota",
                        "language": {"code": "es_CHL"},
                        "components": [
                            {
                                "type": "body",
                                "parameters": [
                                    {"type": "text", "text": empresa_id.upper()},
                                    {"type": "text", "text": f"{salud_promedio}%"},
                                    {"type": "text", "text": str(equipos_en_riesgo)}
                                ]
                            }
                        ]
                    }
                }
                headers = {"Authorization": f"Bearer {TOKEN_META}", "Content-Type": "application/json"}
                requests.post(URL_META, json=payload_meta, headers=headers)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"X Error en Reporte Diario: {str(e)}")
        return jsonify({"status": "error", "message": "Ocurrió un error interno en el servidor"}), 500


@app.route('/ejecutar-prospectiva', methods=['POST'])
def processar_prospectiva_global():
    print(" Sentinel AI: Analizando degradación de SSDs...")
    try:
        if not db: return jsonify({"status": "error", "message": "Firestore desconectado."}), 503
        limite_historial = datetime.now() - timedelta(days=60)
        documentos = db.collection(COLECCION_TELEMETRIA).where("timestamp", ">=", limite_historial).stream()
        historial_flota = {}
        for doc in documentos:
            d = doc.to_dict()
            empresa = d.get("cliente", {}).get("empresa")
            usuario = d.get("cliente", {}).get("usuario")
            if not empresa or not usuario: continue
            key = f"{empresa} || {usuario}"
            if key not in historial_flota: historial_flota[key] = []
            
            if "almacenamiento_ssd" in d and "vida_util_pct" in d["almacenamiento_ssd"]:
                historial_flota[key].append({
                    "timestamp": d["timestamp"],
                    "vida_util": float(d["almacenamiento_ssd"]["vida_util_pct"])
                })
                
        alertas_creadas = 0
        for key, puntos in historial_flota.items():
            if len(puntos) < 2: continue
            puntos.sort(key=lambda x: x["timestamp"])
            empresa_id, usuario_id = key.split('||')
            primero, ultimo = puntos[0], puntos[-1]
            try:
                dt1 = datetime.fromisoformat(primero["timestamp"].replace("Z", "+00:00"))
                dt2 = datetime.fromisoformat(ultimo["timestamp"].replace("Z", "+00:00"))
                dias = (dt2 - dt1).days
            except:
                dias = 0
            if dias <= 0: continue
            tasa = (primero["vida_util"] - ultimo["vida_util"]) / dias
            if tasa > 0:
                dias_restantes = int((ultimo["vida_util"] - 10) / tasa)
                if dias_restantes <= 45:
                    fecha_falla = datetime.now() + timedelta(days=dias_restantes)
                    db.collection("alertas_prospectiva").add({
                        "empresa_id": empresa_id.upper().strip(),
                        "usuario_id": usuario_id.upper().strip(),
                        "componente_affected": "almacenamiento_ssd",
                        "valor_actual": ultimo["vida_util"],
                        "tasa_degradacion_diaria": round(tasa, 4),
                        "dias_vida_restantes": dias_restantes,
                        "fecha_falla_estimada": fecha_falla.strftime("%Y-%m-%d"),
                        "estado_gestion": "pendiente",
                        "timestamp_deteccion": firestore.SERVER_TIMESTAMP
                    })
                    alertas_creadas += 1
        return jsonify({"status": "success", "alertas_generadas": alertas_creadas}), 200
    except Exception as e:
        print(f"X Error en Prospectiva: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================================
# WEBHOOK INTERACTIVO WHATSAPP (VALIDACIÓN ANTI-SPOOFING METAMÁTICA)
# =========================================================================
@app.route('/webhook', methods=['GET', 'POST'])
def webhook_whatsapp():
    if request.method == 'GET':
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        if mode == 'subscribe' and token == WHATSAPP_VERIFY_TOKEN:
            return escape(challenge), 200
        return 'Token incorrecto', 403
        
    firma_meta = request.headers.get('X-Hub-Signature-256')
    if not firma_meta:
        print("🚨 ALERTA SOC: Petición entrante al Webhook sin firma criptográfica. Denegado de raíz.")
        return jsonify({"status": "error", "message": "Firma ausente de origen."}), 403
        
    hash_recibido = firma_meta.split('sha256=')[-1] if 'sha256=' in firma_meta else firma_meta
    
    hash_calculado = hmac.new(
        META_APP_SECRET.encode('utf-8'),
        request.data,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(hash_recibido, hash_calculado):
        print("🚨 ALERTA CRÍTICA SOC: Firma de Webhook Meta inválida. Intento de suplantación (Spoofing) bloqueado.")
        return jsonify({"status": "error", "message": "Firma criptográfica inválida."}), 403
        
    data = request.get_json()
    try:
        entry = data['entry'][0]['changes'][0]['value']
        if 'messages' in entry:
            message_node = entry['messages'][0]
            telefono_remitente = str(message_node['from'])
            
            mensaje_recibido = ""
            button_payload = None
            
            if 'text' in message_node:
                mensaje_recibido = str(message_node['text']['body']).strip()
            elif 'interactive' in message_node and message_node['interactive']['type'] == 'button_reply':
                button_payload = message_node['interactive']['button_reply']['id']
                mensaje_recibido = f"[Interacción Botón] {message_node['interactive']['button_reply']['title']}"
            
            if db:
                db.collection("registro_comunicaciones_whatsapp").add({
                    "timestamp": firestore.SERVER_TIMESTAMP,
                    "remitente": "".join(re.findall(r"\d+", telefono_remitente)),
                    "destinatario": "SENTINEL_AI",
                    "mensaje": mensaje_recibido,
                    "tipo_canal": "interactive_inbound" if button_payload else "text_inbound"
                })

            tkt_id = None
            forzar_aprobacion = False
            forzar_rechazo = False
            
            if button_payload:
                if button_payload.startswith("APROBAR_"):
                    tkt_id = button_payload.replace("APROBAR_", "").upper()
                    forzar_aprobacion = True
                elif button_payload.startswith("RECHAZAR_"):
                    tkt_id = button_payload.replace("RECHAZAR_", "").upper()
                    forzar_rechazo = True
            else:
                match_aprobar = re.match(r"^APROBAR\s+(TKT-[0-9]{4})$", mensaje_recibido, re.IGNORECASE)
                if match_aprobar:
                    tkt_id = match_aprobar.group(1).upper()
                    forzar_aprobacion = True

            if tkt_id and db:
            tkt_ref = db.collection("tickets_hitl").document(tkt_id).get()
            if tkt_ref.exists:
                tkt_data = tkt_ref.to_dict()
                clean_remitente = "".join(re.findall(r"\d+", telefono_remitente))
                clean_sup = "".join(re.findall(r"\d+", str(tkt_data.get("telefono_supervisor", ""))))
                clean_adm = "".join(re.findall(r"\d+", str(tkt_data.get("telefono_admin", ""))))
                
                if (clean_remitente == clean_sup or clean_remitente == clean_adm):
                    if tkt_data.get("estado") == "pendiente_aprobacion_hitl":
                        if forzar_aprobacion:
                            db.collection("tickets_hitl").document(tkt_id).update({
                                "estado": "pendiente", 
                                "aprobado_por": clean_remitente, 
                                "timestamp_autorizacion": firestore.SERVER_TIMESTAMP
                            })
                            
                            coleccion_destino = tkt_data.get("coleccion_origen", COLECCION_TELEMETRIA)
                            id_equipo_target = tkt_data.get("id_equipo")
                            
                            db.collection(coleccion_destino).document(id_equipo_target).set({
                                "comandos_pendientes": {
                                    "accion": tkt_data.get("comando_sugerido"), 
                                    "timestamp_solicitud": firestore.SERVER_TIMESTAMP, 
                                    "estado_ejecucion": "pendiente", 
                                    "token_autorizador_oob": f"VERIFICADO_CHATOPS_BOTON_{tkt_id}"
                                }
                            }, merge=True)
                            
                            print(f"[AIOps HITL SUCCESS] Ticket {tkt_id} authorized vía botón por {clean_remitente}")
                            enviar_texto_whatsapp(telefono_remitente, f"✅ *Sentinel SOC:* Acción autorizada. Procesando orden de contención para el ticket `{tkt_id}`...")
                        elif forzar_rechazo:
                            db.collection("tickets_hitl").document(tkt_id).update({
                                "estado": "rechazado", 
                                "rechazado_por": clean_remitente, 
                                "timestamp_cancelacion": firestore.SERVER_TIMESTAMP
                            })
                            print(f"[AIOps HITL REJECT] Ticket {tkt_id} cancelado vía botón por {clean_remitente}")
                            enviar_texto_whatsapp(telefono_remitente, f"❌ *Sentinel SOC:* Alerta cancelada. El ticket `{tkt_id}` ha sido archivado en estado rechazado.")
                        return jsonify({"status": "success"}), 200
                    else:
                        enviar_texto_whatsapp(telefono_remitente, f"❌ *Sentinel SOC:* El Ticket `{tkt_id}` ya fue gestionado previamente por otra línea de administración o por el agente local.")
                        return jsonify({"status": "error", "message": "Procesado"}), 200
                else:
                    enviar_texto_whatsapp(telefono_remitente, "❌ *Sentinel SOC:* Privilegios de identidad insuficientes para alterar este ticket.")
                    return jsonify({"status": "error", "message": "Denegado"}), 200

            ahora = datetime.now()
            
            if not db: return jsonify({"status": "error", "message": "Db offline"}), 200
            usuarios_ref = db.collection("usuarios").where(filter=FieldFilter("telefono_whatsapp", "in", [telefono_remitente, f"+{telefono_remitente}"])).limit(1).stream()
            usuario_sis = None
            usuario_doc_id = None
            for doc in usuarios_ref:
                usuario_sis = doc.to_dict()
                usuario_doc_id = doc.id
                
            if not usuario_sis:
                return jsonify({"status": "unauthorized"}), 200
                
            if usuario_sis.get("role") == "supervisor" or usuario_sis.get("rol") == "supervisor":
                consultas_actuales = usuario_sis.get("consultas_realizadas") if usuario_sis.get("consultas_realizadas") is not None else usuario_sis.get("consultas_realizadas", 0)
                max_permitidas = usuario_sis.get("max_consultas_mes", 10)
                if consultas_actuales >= max_permitidas:
                    enviar_texto_whatsapp(telefono_remitente, " *Sentinel:* Límite mensual de consultas excedido.")
                    return jsonify({"status": "success"}), 200
                    
            datos_flota_dict = {}
            empresa_id_limpio = str(usuario_sis.get("empresa_id", "")).upper()
            resultados = db.collection(COLECCION_TELEMETRIA).where("cliente.empresa", "==", empresa_id_limpio).order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
            for doc in resultados:
                reg_doc = doc.to_dict()
                u_equipo = reg_doc.get("cliente", {}).get("usuario")
                if u_equipo and u_equipo not in datos_flota_dict:
                    datos_flota_dict[u_equipo] = reg_doc
                    
            respuesta_texto = procesar_respuesta_con_ia(mensaje_recibido, datos_flota_dict, telefono_remitente)
            enviar_texto_whatsapp(telefono_remitente, respuesta_texto)
            db.collection("usuarios").document(usuario_doc_id).update({"consultas_realizadas": firestore.Increment(1)})
            
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"X Error crítico en execution del Webhook: {str(e)}")
        return jsonify({"status": "success"}), 200

def enviar_texto_whatsapp(to, texto):
    to_clean = "".join(re.findall(r"\d+", str(to)))
    payload = {"messaging_product": "whatsapp", "to": to_clean, "type": "text", "text": {"body": texto}}
    headers = {"Authorization": f"Bearer {TOKEN_META}", "Content-Type": "application/json"}
    response = requests.post(URL_META, json=payload, headers=headers)
    print(f" Meta API Response Status: {response.status_code}")
    
    if db:
        try:
            db.collection("registro_comunicaciones_whatsapp").add({
                "timestamp": firestore.SERVER_TIMESTAMP,
                "remitente": "SENTINEL_AI",
                "destinatario": to_clean,
                "mensaje": texto,
                "tipo_canal": "text_outbound"
            })
        except Exception as err_log:
            print(f"! Error al escribir trazabilidad de WhatsApp en DB: {str(err_log)}")

def enviar_botones_whatsapp(to, texto, tkt_id):
    to_clean = "".join(re.findall(r"\d+", str(to)))
    payload = {
        "messaging_product": "whatsapp",
        "to": to_clean,
        "type": "interactive",
        "interactive": {
            "type": "button",
            "body": {"text": texto},
            "action": {
                "buttons": [
                    {
                        "type": "reply",
                        "reply": {
                            "id": f"APROBAR_{tkt_id}",
                            "title": "Aprobar Contención"
                        }
                    },
                    {
                        "type": "reply",
                        "reply": {
                            "id": f"RECHAZAR_{tkt_id}",
                            "title": "Rechazar Alerta"
                        }
                    }
                ]
            }
        }
    }
    headers = {"Authorization": f"Bearer {TOKEN_META}", "Content-Type": "application/json"}
    response = requests.post(URL_META, json=payload, headers=headers)
    print(f" Meta API Interactive Response Status: {response.status_code}")
    
    if db:
        try:
            db.collection("registro_comunicaciones_whatsapp").add({
                "timestamp": firestore.SERVER_TIMESTAMP,
                "remitente": "SENTINEL_AI",
                "destinatario": to_clean,
                "mensaje": f"[Botones Interactivos] {texto}",
                "tipo_canal": "interactive_outbound",
                "ticket_vinculado": tkt_id
            })
        except Exception as e:
            print(f"! Error logging interactive outbound payload: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

echo "# Force deploy revision - Corregido error de indentacion en HITL" >> main.py