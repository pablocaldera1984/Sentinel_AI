# -*- coding: utf-8 -*-
import os
import sys
import time
import ctypes
import threading
import psutil
from typing import List, Dict, Any, Optional
from privacy_compliance import PIIScannerISO29100

try:
    from forensic_zwc import embed_forensic_mark
except ImportError:
    embed_forensic_mark = None

# Constantes Win32 para protección contra capturas de pantalla y Portapapeles
WDA_NONE = 0x00000000
WDA_MONITOR = 0x00000001             # Ventana negra en grabaciones/capturas (Windows 10+)
WDA_EXCLUDEFROMCAPTURE = 0x00000011  # Exclusión total de render (Windows 10 2004+)
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

# Lista blanca corporativa de binarios autorizados para interactuar con la bóveda
AUTHORIZED_PROCESS_NAMES = {
    "excel.exe", "winword.exe", "powerpnt.exe",
    "acrord32.exe", "acrobat.exe", "notepad.exe",
    "textedit", "preview", "pages", "numbers"
}


class ScreenCaptureShield:
    """
    Aplica protección contra software de captura, grabación de pantalla o transmisiones
    en vivo (Teams, Discord, AnyDesk, Zoom) mediante la API Win32 SetWindowDisplayAffinity.
    """
    @staticmethod
    def protect_hwnd(hwnd: int) -> bool:
        if sys.platform != "win32":
            return True
        try:
            user32 = ctypes.windll.user32
            result = user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
            return result != 0
        except Exception:
            return False


class ProcessPIDGuard:
    """
    Micro-DLP por proceso invocador: valida que únicamente aplicaciones de productividad
    legítimas puedan acceder a los descriptores de archivo del enclave.
    """
    def __init__(self, allowed_processes: Optional[set] = None):
        self.allowed_processes = {p.lower() for p in (allowed_processes or AUTHORIZED_PROCESS_NAMES)}

    def inspect_process(self, pid: int) -> Dict[str, Any]:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            proc_exe = proc.exe()

            is_authorized = proc_name in self.allowed_processes
            return {
                "authorized": is_authorized,
                "pid": pid,
                "name": proc_name,
                "path": proc_exe,
                "action": "ALLOW" if is_authorized else "TERMINATE_AND_ALERT"
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {
                "authorized": False,
                "pid": pid,
                "name": "UNKNOWN",
                "error": str(e),
                "action": "BLOCK"
            }


class ActiveClipboardShield:
    """
    Guardián activo del portapapeles: intercepta eventos de copia, enmascara en caliente
    RUTs o tarjetas (Ley 21.719) e inyecta esteganografía forense invisible (ZWC).
    """
    def __init__(self, pii_scanner: PIIScannerISO29100, user_id: int = 101, device_id: int = 402):
        self.scanner = pii_scanner
        self.user_id = user_id
        self.device_id = device_id
        self.monitoring = False
        self._last_content = ""
        self.sanitized_incidents_count = 0

    def _read_win32_clipboard(self) -> str:
        if sys.platform != "win32":
            return ""
        texto = ""
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            if user32.OpenClipboard(0):
                try:
                    if user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                        h_data = user32.GetClipboardData(CF_UNICODETEXT)
                        if h_data:
                            kernel32.GlobalLock.restype = ctypes.c_wchar_p
                            ptr = kernel32.GlobalLock(h_data)
                            if ptr:
                                texto = str(ptr)
                                kernel32.GlobalUnlock(h_data)
                finally:
                    user32.CloseClipboard()
        except Exception:
            pass
        return texto

    def _write_win32_clipboard(self, text: str):
        if sys.platform != "win32":
            return
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            if user32.OpenClipboard(0):
                try:
                    user32.EmptyClipboard()
                    data_bytes = (text + "\0").encode("utf-16le")
                    h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data_bytes))
                    if h_mem:
                        kernel32.GlobalLock.restype = ctypes.c_void_p
                        ptr = kernel32.GlobalLock(h_mem)
                        if ptr:
                            ctypes.memmove(ptr, data_bytes, len(data_bytes))
                            kernel32.GlobalUnlock(h_mem)
                            user32.SetClipboardData(CF_UNICODETEXT, h_mem)
                finally:
                    user32.CloseClipboard()
        except Exception:
            pass

    def inspect_and_sanitize(self, raw_text: str) -> tuple:
        sanitized_text, was_modified = self.scanner.sanitize_clipboard(raw_text)
        if was_modified:
            self.sanitized_incidents_count += 1
        # Inyectar huella esteganográfica ZWC si el texto tiene más de 25 caracteres
        if embed_forensic_mark and len(sanitized_text) > 25:
            horas_ts = int(time.time() // 3600) & 0xFFFF
            sanitized_text = embed_forensic_mark(sanitized_text, self.user_id, self.device_id, horas_ts)
        return sanitized_text, was_modified

    def start_background_sanitizer(self, poll_interval: float = 0.8):
        """Inicia hilo de supervisión en vivo del portapapeles de Windows."""
        self.monitoring = True

        def _loop():
            while self.monitoring:
                try:
                    actual = self._read_win32_clipboard()
                    if actual and actual != self._last_content:
                        limpio, modificado = self.inspect_and_sanitize(actual)
                        if modificado or limpio != actual:
                            self._write_win32_clipboard(limpio)
                            self._last_content = limpio
                        else:
                            self._last_content = actual
                except Exception:
                    pass
                time.sleep(poll_interval)

        thread = threading.Thread(target=_loop, daemon=True)
        thread.start()

    def stop(self):
        self.monitoring = False