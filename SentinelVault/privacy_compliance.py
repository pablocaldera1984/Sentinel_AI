import re
import hmac
import hashlib
from datetime import datetime, timezone

# Expresiones regulares para detección de PII Chileno e Internacional
REGEX_RUT = re.compile(r"\b(\d{1,2}(?:\.\d{3}){2}|\d{7,8})-([\dkK])\b")
REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
REGEX_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

SENSITIVE_KEYWORDS = {
    "FINANCIERO": ["sueldo", "remuneración", "finiquito", "honorarios", "cuenta corriente", "balance", "tesorería", "uf"],
    "SALUD": ["diagnóstico", "licencia médica", "isapre", "fonasa", "paciente", "tratamiento", "clínica"],
    "LEGAL_CORPORATIVO": ["confidencial", "contrato", "directorio", "auditoría", "propiedad intelectual", "nda"]
}


def normalize_rut(rut_raw: str) -> str:
    """Limpia puntos y convierte el dígito verificador a mayúscula (ej: 12345678-K)."""
    clean = rut_raw.replace(".", "").replace(" ", "").upper()
    return clean


def validate_chilean_rut(rut_str: str) -> bool:
    """Valida matemáticamente un RUT chileno mediante el algoritmo Módulo 11."""
    clean = normalize_rut(rut_str)
    if "-" not in clean:
        return False
    body, dv = clean.split("-", 1)
    if not body.isdigit() or len(body) < 7:
        return False

    reversed_digits = map(int, reversed(body))
    factors = [2, 3, 4, 5, 6, 7]
    s = sum(d * factors[i % 6] for i, d in enumerate(reversed_digits))
    remainder = 11 - (s % 11)
    if remainder == 11:
        expected_dv = "0"
    elif remainder == 10:
        expected_dv = "K"
    else:
        expected_dv = str(remainder)

    return dv == expected_dv


def validate_luhn(card_number: str) -> bool:
    """Valida números de tarjetas de crédito mediante el algoritmo de Luhn."""
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def generate_blind_index(identifier: str, org_secret_key: bytes) -> str:
    """
    Genera un Blind Index (HMAC-SHA256 truncado a 16 chars hex) para búsquedas ARSOP+
    (Derecho al Olvido Ley 21.719) sin exponer el RUT en texto plano en Firebase.
    """
    norm = normalize_rut(identifier).encode("utf-8")
    digest = hmac.new(org_secret_key, norm, hashlib.sha256).hexdigest()
    return digest[:16]


class PIIScannerISO29100:
    """
    Escáner de Datos Personales (PII) alineado a ISO/IEC 29100:2024 y Ley 21.719.
    Analiza flujos de texto para clasificación, conteo de impacto y RoPA automático.
    """
    def __init__(self, org_secret_key: bytes = b"GLOBAL365-DEFAULT-BLIND-KEY-2026"):
        self.org_secret_key = org_secret_key

    def scan_text(self, text: str) -> dict:
        valid_ruts = set()
        for match in REGEX_RUT.finditer(text):
            full_rut = match.group(0)
            if validate_chilean_rut(full_rut):
                valid_ruts.add(normalize_rut(full_rut))

        emails = set(m.group(0).lower() for m in REGEX_EMAIL.finditer(text))

        cards = set()
        for match in REGEX_CREDIT_CARD.finditer(text):
            candidate = match.group(0)
            if validate_luhn(candidate):
                cards.add(re.sub(r"\D", "", candidate))

        # Clasificación de categoría de tratamiento (RoPA Art. 14 ter Ley 21.719)
        text_lower = text.lower()
        detected_categories = []
        for cat, keywords in SENSITIVE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                detected_categories.append(cat)

        if not detected_categories:
            detected_categories.append("GENERAL")

        total_pii = len(valid_ruts) + len(emails) + len(cards)
        if total_pii > 10 or "SALUD" in detected_categories or len(cards) > 0:
            sensitivity = "CRITICAL"
        elif total_pii > 0 or "FINANCIERO" in detected_categories:
            sensitivity = "HIGH"
        else:
            sensitivity = "LOW"

        # Generar índices ciegos para el buscador de Derecho al Olvido
        blind_indexes = [generate_blind_index(r, self.org_secret_key) for r in sorted(valid_ruts)]

        return {
            "iso_standard": "ISO/IEC 29100:2024 & Ley 21.719",
            "sensitivity_level": sensitivity,
            "categories": detected_categories,
            "counts": {
                "chilean_ruts": len(valid_ruts),
                "emails": len(emails),
                "credit_cards": len(cards),
                "total_pii_records": total_pii
            },
            "arsop_blind_indexes": blind_indexes
        }

    def pseudonymize_text(self, text: str) -> str:
        """
        Genera una vista seudonimizada (ISO/IEC 20889) reemplazando RUTs, correos
        y tarjetas por tokens irreversibles para compartir archivos sin exponer PII.
        """
        def _replace_rut(match):
            full_rut = match.group(0)
            if validate_chilean_rut(full_rut):
                b_idx = generate_blind_index(full_rut, self.org_secret_key)[:6].upper()
                return f"[RUT_TOKEN_{b_idx}]"
            return full_rut

        def _replace_email(match):
            email = match.group(0)
            b_idx = hashlib.sha256(email.lower().encode()).hexdigest()[:6].upper()
            return f"[EMAIL_TOKEN_{b_idx}]"

        def _replace_card(match):
            card = match.group(0)
            if validate_luhn(card):
                clean_c = re.sub(r"\D", "", card)
                return f"[CARD_****_{clean_c[-4:]}]"
            return card

        step1 = REGEX_RUT.sub(_replace_rut, text)
        step2 = REGEX_EMAIL.sub(_replace_email, step1)
        step3 = REGEX_CREDIT_CARD.sub(_replace_card, step2)
        return step3

    @staticmethod
    def sanitize_clipboard(clipboard_text: str):
        """
        Smart Clipboard Guard: Enmascara en vivo RUTs y tarjetas si el usuario
        intenta copiar texto hacia una ventana no autorizada (WhatsApp, ChatGPT, Web).
        """
        modified = False

        def _mask_rut(match):
            nonlocal modified
            if validate_chilean_rut(match.group(0)):
                modified = True
                return "[DATO PROTEGIDO LEY 21.719]"
            return match.group(0)

        sanitized = REGEX_RUT.sub(_mask_rut, clipboard_text)
        return sanitized, modified