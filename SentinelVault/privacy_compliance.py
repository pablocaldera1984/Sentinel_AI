# -*- coding: utf-8 -*-
import os
import re
import hmac
import hashlib
import unicodedata
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

# Librerías opcionales para inspección y edición quirúrgica profunda (Office & PDF)
try:
    import openpyxl
except ImportError:
    openpyxl = None

try:
    import docx
except ImportError:
    docx = None

try:
    import fitz  # PyMuPDF para lectura y censura/redacción nativa en PDF
except ImportError:
    fitz = None

# Expresiones regulares para detección de PII Chileno e Internacional
# Soporta 12.345.678-9, 12345678-9 y variantes con K
REGEX_RUT = re.compile(r"\b(\d{1,2}(?:\.\d{3}){2}|\d{7,8})-([\dkK])\b")
REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
REGEX_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

SENSITIVE_KEYWORDS = {
    "FINANCIERO": ["sueldo", "remuneración", "finiquito", "honorarios", "cuenta corriente", "balance", "tesorería", "uf"],
    "SALUD": ["diagnóstico", "licencia médica", "isapre", "fonasa", "paciente", "tratamiento", "clínica", "ficha clínica", "anamnesis"],
    "LEGAL_CORPORATIVO": ["confidencial", "contrato", "directorio", "auditoría", "propiedad intelectual", "nda"]
}

SUPPORTED_SCAN_EXTENSIONS = (".txt", ".csv", ".log", ".md", ".json", ".xlsx", ".docx", ".pdf")


def normalize_rut(rut_raw: str) -> str:
    """
    Limpia puntos, espacios y normaliza al formato estándar chileno 12345678-K.
    Soporta incluso entrada continua sin guion (ej: 123456789 -> 12345678-9).
    """
    clean = re.sub(r"[^0-9kK]", "", str(rut_raw or "")).upper()
    if len(clean) >= 8:
        return f"{clean[:-1]}-{clean[-1]}"
    return str(rut_raw or "").replace(".", "").replace(" ", "").upper()


def validate_chilean_rut(rut_str: str) -> bool:
    """Valida matemáticamente un RUT chileno mediante el algoritmo Módulo 11."""
    clean = normalize_rut(rut_str)
    if "-" not in clean:
        return False
    body, dv = clean.split("-", 1)
    if not body.isdigit() or len(body) < 7 or len(body) > 8:
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
    (Derecho al Olvido Ley 21.719) sin exponer el RUT o nombre en texto plano en Firebase.
    """
    raw_clean = str(identifier or "").strip()
    if re.search(r"\d{7,8}", raw_clean.replace(".", "")):
        norm = normalize_rut(raw_clean).encode("utf-8")
    else:
        # Normalización canónica para nombres (sin tildes, minúsculas, sin separadores)
        sin_tildes = "".join(
            c for c in unicodedata.normalize("NFD", raw_clean.lower())
            if unicodedata.category(c) != "Mn"
        )
        norm = re.sub(r"[^a-z0-9]", "", sin_tildes).encode("utf-8")
    digest = hmac.new(org_secret_key, norm, hashlib.sha256).hexdigest()
    return digest[:16]


def build_flexible_search_regex(query_str: str) -> re.Pattern:
    """
    Construye un patrón Regex ultra-versátil para encontrar un RUT o Nombre en cualquier formato:
    - Si es un RUT (ej. '12.345.678-9' o '12345678-9' o '123456789'): coincide con o sin puntos y con o sin guion.
    - Si es un Nombre (ej. 'Juan Pérez', 'juan_perez', 'juanperez'): coincide ignorando mayúsculas,
      tildes, guiones bajos, puntos, espacios múltiples o escritura continua sin espacios.
    """
    q_clean = str(query_str or "").strip()
    solo_alnum_rut = re.sub(r"[^0-9kK]", "", q_clean).upper()

    # Caso 1: Es un RUT chileno (7 u 8 dígitos + DV)
    if len(solo_alnum_rut) in (8, 9) and solo_alnum_rut[:-1].isdigit():
        cuerpo = solo_alnum_rut[:-1]
        dv = solo_alnum_rut[-1]
        if len(cuerpo) == 8:
            p1, p2, p3 = cuerpo[:2], cuerpo[2:5], cuerpo[5:8]
        else:
            p1, p2, p3 = cuerpo[:1], cuerpo[1:4], cuerpo[4:7]
        # Permite puntos opcionales, espacios opcionales y guion opcional
        pat = rf"(?<!\d){p1}\.?\s?{p2}\.?\s?{p3}\s?-?\s?[{dv.lower()}{dv.upper()}](?!\d)"
        return re.compile(pat)

    # Caso 2: Es un Nombre o término libre (ej. "Juan Pérez", "juan_perez", "juanperez")
    sin_tildes = "".join(
        c for c in unicodedata.normalize("NFD", q_clean.lower())
        if unicodedata.category(c) != "Mn"
    )
    mapa_vocales = {
        "a": "[aáàäâAÁÀÄÂ]",
        "e": "[eéèëêEÉÈËÊ]",
        "i": "[iíìïîIÍÌÏÎ]",
        "o": "[oóòöôOÓÒÖÔ]",
        "u": "[uúùüûUÚÙÜÛ]",
        "n": "[nñNÑ]"
    }
    # Separar por espacios, guiones bajos, puntos o guiones
    tokens = [t for t in re.split(r"[\s_\.\-]+", sin_tildes) if t]
    if not tokens:
        return re.compile(re.escape(q_clean), re.IGNORECASE)

    partes_regex = []
    for tok in tokens:
        tok_pat = ""
        for ch in tok:
            if ch in mapa_vocales:
                tok_pat += mapa_vocales[ch]
            elif ch.isalnum():
                tok_pat += f"[{ch.lower()}{ch.upper()}]"
            else:
                tok_pat += re.escape(ch)
        partes_regex.append(tok_pat)

    # Entre palabras permite: nada (juanperez), espacios, guiones bajos (_), puntos (.) o guiones (-)
    full_pattern = r"[\s_\.\-]*".join(partes_regex)
    return re.compile(full_pattern, re.IGNORECASE)


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


class DeepDiskPIIRemediator:
    """
    Rastreador Profundo Multi-Formato y Motor de Supresión Quirúrgica In-Situ (Ley 21.719).
    - Recorre todas las carpetas de usuario del PC (Desktop, Documents, Downloads, OneDrive).
    - Inspecciona el interior de .xlsx, .docx, .pdf, .csv, .txt, .json, .md.
    - Sobreescribe exclusivamente el RUT o Nombre solicitado sin alterar los datos de terceros.
    """
    def __init__(self, org_secret_key: bytes = b"GLOBAL365-DEFAULT-BLIND-KEY-2026"):
        self.org_secret_key = org_secret_key
        self.scanner = PIIScannerISO29100(org_secret_key=org_secret_key)

    @staticmethod
    def get_user_document_roots() -> List[str]:
        """Obtiene todas las carpetas reales de documentos de todos los usuarios humanos del PC."""
        roots = []
        base_users = os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users")
        subfolders = [
            "Desktop", "Documents", "Downloads",
            os.path.join("OneDrive", "Desktop"),
            os.path.join("OneDrive", "Documents"),
            os.path.join("OneDrive", "Escritorio"),
            os.path.join("OneDrive", "Documentos"),
            "Escritorio", "Documentos", "Descargas"
        ]
        if os.path.exists(base_users):
            try:
                for u in os.listdir(base_users):
                    if u.lower() in ["public", "default", "default user", "all users", "systemprofile"]:
                        continue
                    u_dir = os.path.join(base_users, u)
                    if not os.path.isdir(u_dir):
                        continue
                    for sub in subfolders:
                        cand = os.path.join(u_dir, sub)
                        if os.path.exists(cand) and cand not in roots:
                            roots.append(cand)
            except Exception:
                pass

        if not roots:
            prof = os.environ.get("USERPROFILE", os.path.expanduser("~"))
            for sub in ["Desktop", "Documents", "Downloads"]:
                cand = os.path.join(prof, sub)
                if os.path.exists(cand):
                    roots.append(cand)
        return roots

    @staticmethod
    def extract_text_from_file(file_path: str) -> str:
        """Extrae el texto completo del interior de un archivo (.xlsx, .docx, .pdf o texto plano)."""
        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext in (".txt", ".csv", ".log", ".md", ".json"):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read(2 * 1024 * 1024)  # Hasta 2 MB de texto

            elif ext == ".xlsx" and openpyxl is not None:
                wb = openpyxl.load_workbook(file_path, data_only=True, read_only=True)
                chunks = []
                for sheet in wb.worksheets:
                    for row in sheet.iter_rows(values_only=True):
                        for cell_val in row:
                            if cell_val is not None:
                                chunks.append(str(cell_val))
                wb.close()
                return " ".join(chunks)

            elif ext == ".docx" and docx is not None:
                doc = docx.Document(file_path)
                chunks = [p.text for p in doc.paragraphs if p.text]
                for table in doc.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            if cell.text:
                                chunks.append(cell.text)
                return "\n".join(chunks)

            elif ext == ".pdf" and fitz is not None:
                doc = fitz.open(file_path)
                chunks = []
                for page in doc:
                    chunks.append(page.get_text("text"))
                doc.close()
                return "\n".join(chunks)
        except Exception:
            pass
        return ""

    def search_across_pc(
        self,
        target_queries: List[str],
        extra_roots: Optional[List[str]] = None,
        max_files: int = 1500
    ) -> Dict[str, Any]:
        """
        Busca uno o múltiples términos (ej. RUT y Nombre: ['12.345.678-9', 'Juan Pérez'])
        en el nombre y en el interior de todos los archivos soportados del PC.
        """
        queries = [q.strip() for q in target_queries if q and str(q).strip()]
        patterns = [(q, build_flexible_search_regex(q)) for q in queries]

        search_roots = self.get_user_document_roots()
        if extra_roots:
            for r in extra_roots:
                if r and os.path.exists(r) and r not in search_roots:
                    search_roots.append(r)

        matches_found = []
        files_inspected = 0
        visited_paths = set()

        for root_dir in search_roots:
            for dirpath, dirnames, filenames in os.walk(root_dir):
                # Evitar carpetas ocultas o de sistema pesadas
                dirnames[:] = [d for d in dirnames if not d.startswith(".") and d.lower() not in ("node_modules", "appdata", "venv", "__pycache__")]
                for fname in filenames:
                    if files_inspected >= max_files:
                        break
                    if fname.startswith("~$") or not fname.lower().endswith(SUPPORTED_SCAN_EXTENSIONS):
                        continue

                    full_path = os.path.normpath(os.path.join(dirpath, fname))
                    if full_path in visited_paths:
                        continue
                    visited_paths.add(full_path)

                    try:
                        if os.path.getsize(full_path) > 25 * 1024 * 1024:  # Ignorar archivos > 25 MB
                            continue
                    except Exception:
                        continue

                    files_inspected += 1
                    content_text = self.extract_text_from_file(full_path)
                    combined_target = f"{fname}\n{content_text}"

                    total_occurrences = 0
                    matched_snippets = []
                    for q_raw, rgx in patterns:
                        found = list(rgx.finditer(combined_target))
                        if found:
                            total_occurrences += len(found)
                            for m in found[:3]:
                                start = max(0, m.start() - 25)
                                end = min(len(combined_target), m.end() + 25)
                                snippet = combined_target[start:end].replace("\n", " ").strip()
                                matched_snippets.append(snippet)

                    if total_occurrences > 0:
                        pii_meta = self.scanner.scan_text(content_text[:200000])
                        matches_found.append({
                            "file_name": fname,
                            "full_path": full_path,
                            "extension": os.path.splitext(fname)[1].lower(),
                            "occurrences": total_occurrences,
                            "snippets": matched_snippets[:3],
                            "sensitivity": pii_meta["sensitivity_level"],
                            "categories": pii_meta["categories"],
                            "total_ruts_in_file": pii_meta["counts"]["chilean_ruts"],
                            "size_bytes": os.path.getsize(full_path)
                        })

        return {
            "queries": queries,
            "files_inspected": files_inspected,
            "total_files_matched": len(matches_found),
            "matches": matches_found,
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
        }

    def surgical_redact_file(
        self,
        file_path: str,
        target_queries: List[str],
        acta_id: str = "ARSOP-21719"
    ) -> Dict[str, Any]:
        """
        Sobreescribe exclusivamente las apariciones del RUT o Nombre buscado dentro del archivo
        (.xlsx, .docx, .pdf, .csv, .txt), preservando intactos los datos de todas las demás personas.
        """
        if not os.path.exists(file_path):
            return {"success": False, "file_path": file_path, "error": "Archivo no encontrado"}

        queries = [q.strip() for q in target_queries if q and str(q).strip()]
        patterns = [build_flexible_search_regex(q) for q in queries]
        replacement_tag = f"[SUPRIMIDO LEY 21.719 #{acta_id}]"
        ext = os.path.splitext(file_path)[1].lower()
        redacted_count = 0

        try:
            # 1. Archivos de texto plano / CSV / Markdown / JSON
            if ext in (".txt", ".csv", ".log", ".md", ".json"):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                new_text = text
                for rgx in patterns:
                    new_text, n_subs = rgx.subn(replacement_tag, new_text)
                    redacted_count += n_subs
                if redacted_count > 0:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_text)

            # 2. Planillas Microsoft Excel (.xlsx)
            elif ext == ".xlsx" and openpyxl is not None:
                wb = openpyxl.load_workbook(file_path)
                for sheet in wb.worksheets:
                    for row in sheet.iter_rows():
                        for cell in row:
                            if cell.value is not None:
                                val_str = str(cell.value)
                                new_val = val_str
                                cell_modified = False
                                for rgx in patterns:
                                    new_val, n_subs = rgx.subn(replacement_tag, new_val)
                                    if n_subs > 0:
                                        redacted_count += n_subs
                                        cell_modified = True
                                if cell_modified:
                                    cell.value = new_val
                if redacted_count > 0:
                    wb.save(file_path)
                wb.close()

            # 3. Documentos Microsoft Word (.docx)
            elif ext == ".docx" and docx is not None:
                doc = docx.Document(file_path)
                for p in doc.paragraphs:
                    if p.text:
                        new_p = p.text
                        p_mod = False
                        for rgx in patterns:
                            new_p, n_subs = rgx.subn(replacement_tag, new_p)
                            if n_subs > 0:
                                redacted_count += n_subs
                                p_mod = True
                        if p_mod:
                            p.text = new_p
                for table in doc.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            for p in cell.paragraphs:
                                if p.text:
                                    new_p = p.text
                                    p_mod = False
                                    for rgx in patterns:
                                        new_p, n_subs = rgx.subn(replacement_tag, new_p)
                                        if n_subs > 0:
                                            redacted_count += n_subs
                                            p_mod = True
                                    if p_mod:
                                        p.text = new_p
                if redacted_count > 0:
                    doc.save(file_path)

            # 4. Documentos PDF (.pdf) mediante Redacción Física PyMuPDF
            elif ext == ".pdf" and fitz is not None:
                doc = fitz.open(file_path)
                for page in doc:
                    page_text = page.get_text("text")
                    matched_strings = set()
                    for rgx in patterns:
                        for m in rgx.finditer(page_text):
                            matched_strings.add(m.group(0))
                    for target_str in matched_strings:
                        areas = page.search_for(target_str)
                        for rect in areas:
                            page.add_redact_annot(
                                rect,
                                text=replacement_tag,
                                fill=(0.1, 0.1, 0.1),
                                text_color=(1, 1, 1)
                            )
                            redacted_count += 1
                    if matched_strings:
                        page.apply_redactions()
                if redacted_count > 0:
                    temp_pdf = file_path + ".tmp_redact.pdf"
                    doc.save(temp_pdf, garbage=4, deflate=True)
                    doc.close()
                    os.replace(temp_pdf, file_path)
                else:
                    doc.close()

            with open(file_path, "rb") as f_hash:
                post_sha256 = hashlib.sha256(f_hash.read()).hexdigest()

            return {
                "success": True,
                "file_name": os.path.basename(file_path),
                "file_path": file_path,
                "redacted_instances": redacted_count,
                "replacement_applied": replacement_tag,
                "post_sanitization_sha256": post_sha256
            }
        except Exception as e:
            return {
                "success": False,
                "file_name": os.path.basename(file_path),
                "file_path": file_path,
                "error": str(e)
            }