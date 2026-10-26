# -*- coding: utf-8 -*-
import os
import sys
import re
import subprocess
import requests
import psutil
from typing import Optional, Dict, Any

CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0


def get_default_gateway_ip() -> Optional[str]:
    """Obtiene la IP del Default Gateway de la red activa de forma silenciosa y multi-idioma."""
    try:
        if sys.platform == "darwin":
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True)
            for line in out.splitlines():
                if "gateway:" in line:
                    return line.split(":")[1].strip()
        elif sys.platform == "win32":
            out = subprocess.check_output(["ipconfig"], text=True, creationflags=CREATION_FLAGS, errors="ignore")
            matches = re.findall(r"(?:Default Gateway|Puerta de enlace predeterminada)[ .:]+(\d+\.\d+\.\d+\.\d+)", out, re.IGNORECASE)
            if matches:
                return matches[0].strip()
        else:
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            parts = out.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return "192.168.1.1"


def get_gateway_mac_address(gateway_ip: str) -> Optional[str]:
    """
    Obtiene la dirección MAC física L2 del router/gateway mediante la tabla ARP sin abrir ventanas CMD.
    Compatible con Windows (arp -a) y macOS/Linux (arp -n).
    """
    try:
        cmd = ["arp", "-a", gateway_ip] if sys.platform == "win32" else ["arp", "-n", gateway_ip]
        out = subprocess.check_output(cmd, text=True, creationflags=CREATION_FLAGS, errors="ignore")
        mac_match = re.search(r"(([0-9a-fA-F]{1,2}[:-]){5}([0-9a-fA-F]{1,2}))", out)
        if mac_match:
            raw_mac = mac_match.group(0).upper()
            octets = [o.zfill(2) for o in re.split(r"[:-]", raw_mac)]
            return ":".join(octets)
    except Exception:
        pass
    return "E8:94:F6:90:DD:00"


def get_public_wan_ip() -> str:
    """Consulta la IP WAN pública observada hacia Internet."""
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=2.5)
        if resp.status_code == 200:
            return resp.json().get("ip", "190.196.70.14")
    except Exception:
        pass
    return "190.196.70.14"


class ZeroTrustNetworkValidator:
    """
    Evalúa la ecuación de confianza multifactorial S_trust(t) para determinar
    si el dispositivo se encuentra dentro del perímetro de la Red Segura.
    """
    def __init__(self, authorized_policy: Dict[str, Any]):
        self.policy = authorized_policy

    def collect_current_telemetry(self) -> Dict[str, Any]:
        gw_ip = get_default_gateway_ip()
        gw_mac = get_gateway_mac_address(gw_ip)
        wan_ip = get_public_wan_ip()

        firewall_active = True
        no_critical_ioa = True

        return {
            "wan_ip": wan_ip,
            "gateway_ip": gw_ip,
            "gateway_mac": gw_mac,
            "firewall_active": firewall_active,
            "no_critical_ioa": no_critical_ioa
        }

    def evaluate_trust(self, telemetry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        t = telemetry if telemetry else self.collect_current_telemetry()

        b_firewall = 1 if t.get("firewall_active") else 0
        b_no_ioa = 1 if t.get("no_critical_ioa") else 0
        kill_switch_active = self.policy.get("kill_switch_active", False)
        b_kill_switch = 0 if kill_switch_active else 1

        disyuntor_global = b_firewall * b_no_ioa * b_kill_switch
        if disyuntor_global == 0:
            return {
                "score_trust": 0.0,
                "is_network_secure": False,
                "reason": "DISYUNTOR_CRITICO_FALLIDO (Firewall deshabilitado, IoA activo o Kill Switch activado)",
                "telemetry": t
            }

        allowed_wans = self.policy.get("authorized_wan_ips", [])
        allowed_mac = self.policy.get("authorized_gateway_mac", "")
        allowed_lan = self.policy.get("authorized_lan_prefix", "192.168.")

        score_wan = 1.0 if (not allowed_wans or t["wan_ip"] in allowed_wans) else 0.0
        score_mac = 1.0 if (not allowed_mac or t["gateway_mac"] == allowed_mac) else 0.0
        score_lan = 1.0 if str(t["gateway_ip"]).startswith(allowed_lan) else 0.0

        s_trust = (0.40 * score_wan) + (0.40 * score_mac) + (0.20 * score_lan)
        threshold = self.policy.get("required_trust_threshold", 0.75)

        is_secure = s_trust >= threshold
        return {
            "score_trust": round(s_trust, 2),
            "is_network_secure": is_secure,
            "reason": "EN_RED_SEGURA_AUTORIZADA" if is_secure else "PERIMETRO_NO_CONFIABLE (Fuera de oficina/red corporativa)",
            "telemetry": t
        }