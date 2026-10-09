"""Stealth Mode & Onion Node (Tor) Traffic Camouflage Service.

Provides OpSec privacy controls by routing reconnaissance, scraping, and OSINT
traffic through Tor SOCKS5 / Onion proxy gateways, preventing investigator IP leakage.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
import socket
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("mcp_sec_analyzer.core.stealth")

CONFIG_PATH = Path(".mcp_memory") / "stealth_config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "proxy_url": "socks5://127.0.0.1:9050",
    "dns_over_tor": True,
    "last_tested": None,
    "last_status": "untested",
    "last_exit_ip": None,
    "is_tor": False,
}


def load_stealth_config() -> dict[str, Any]:
    """Load persisted stealth configuration or default."""
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            merged = {**DEFAULT_CONFIG, **data}
            return merged
        except Exception as e:
            logger.warning(f"Error reading stealth config: {e}. Using defaults.")
    return dict(DEFAULT_CONFIG)


def save_stealth_config(config: dict[str, Any]) -> None:
    """Save stealth configuration to disk."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to persist stealth config: {e}")


def normalize_proxy_url(proxy_url: str, dns_over_tor: bool = True) -> str:
    """Normalize proxy URL to ensure proper SOCKS5/SOCKS5h scheme."""
    cleaned = proxy_url.strip()
    if not cleaned:
        cleaned = "127.0.0.1:9050"

    if not cleaned.startswith(("socks5://", "socks5h://", "socks4://", "http://", "https://")):
        scheme = "socks5h://" if dns_over_tor else "socks5://"
        cleaned = f"{scheme}{cleaned}"
    elif dns_over_tor and cleaned.startswith("socks5://"):
        cleaned = "socks5h://" + cleaned[len("socks5://"):]
    elif not dns_over_tor and cleaned.startswith("socks5h://"):
        cleaned = "socks5://" + cleaned[len("socks5h://"):]

    return cleaned


def parse_host_port(proxy_url: str) -> tuple[str, int]:
    """Extract host and port from a proxy URL string."""
    cleaned = proxy_url.strip()
    # Strip scheme if present
    match = re.search(r"://([^/]+)", cleaned)
    netloc = match.group(1) if match else cleaned
    if ":" in netloc:
        parts = netloc.split(":")
        host = parts[0] or "127.0.0.1"
        try:
            port = int(parts[1])
        except ValueError:
            port = 9050
        return host, port
    return netloc or "127.0.0.1", 9050


def test_tor_connection(proxy_url: str | None = None, timeout: float = 6.0) -> dict[str, Any]:
    """Test connectivity to the Tor / Onion node and verify external IP masking."""
    cfg = load_stealth_config()
    target_proxy = proxy_url or cfg.get("proxy_url", "socks5://127.0.0.1:9050")
    normalized = normalize_proxy_url(target_proxy, dns_over_tor=cfg.get("dns_over_tor", True))
    host, port = parse_host_port(normalized)

    # 1. Test socket connectivity to Tor gateway
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.5)
    try:
        res = sock.connect_ex((host, port))
        if res != 0:
            sock.close()
            return {
                "status": "unreachable",
                "connected": False,
                "is_tor": False,
                "proxy_url": normalized,
                "host": host,
                "port": port,
                "message": f"Nó Onion / Proxy Tor inacessível em {host}:{port}.",
                "instructions": (
                    "Para usar o modo stealth, inicie o daemon do Tor (ex: 'tor.exe' na porta 9050), "
                    "inicie o Tor Browser (porta 9150) ou configure um container Docker (ex: dperson/torproxy)."
                ),
            }
        sock.close()
    except Exception as e:
        return {
            "status": "error",
            "connected": False,
            "is_tor": False,
            "proxy_url": normalized,
            "error": str(e),
            "message": f"Erro de conexão com o socket do nó Tor em {host}:{port}.",
        }

    # 2. Probe external Tor check service through the SOCKS5 proxy
    try:
        import requests

        proxies = {
            "http": normalized,
            "https": normalized,
        }

        # Check official Tor project API
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"}
        resp = requests.get(
            "https://check.torproject.org/api/ip",
            proxies=proxies,
            timeout=timeout,
            headers=headers,
        )

        if resp.status_code == 200:
            data = resp.json()
            is_tor = bool(data.get("IsTor", True))
            ip = data.get("IP", "Desconhecido")

            # Update cache in config
            cfg["last_tested"] = data
            cfg["last_status"] = "active"
            cfg["last_exit_ip"] = ip
            cfg["is_tor"] = is_tor
            save_stealth_config(cfg)

            return {
                "status": "active",
                "connected": True,
                "is_tor": is_tor,
                "exit_ip": ip,
                "proxy_url": normalized,
                "host": host,
                "port": port,
                "message": f"Nó Onion conectado com sucesso! Tráfego camuflado através do IP de saída {ip}.",
            }

    except Exception as e:
        # Fallback probe through generic IP reflection
        try:
            import requests
            proxies = {"http": normalized, "https": normalized}
            resp = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=timeout)
            if resp.status_code == 200:
                ip = resp.json().get("ip", "Desconhecido")
                return {
                    "status": "active",
                    "connected": True,
                    "is_tor": True,
                    "exit_ip": ip,
                    "proxy_url": normalized,
                    "message": f"Proxy SOCKS5 funcional! IP de saída mascarado: {ip}.",
                }
        except Exception as e2:
            pass

        return {
            "status": "proxy_ready_upstream_failed",
            "connected": True,
            "is_tor": False,
            "proxy_url": normalized,
            "host": host,
            "port": port,
            "error": str(e),
            "message": f"A porta {port} do proxy está aberta, mas a requisição externa falhou (possível circuito Tor ainda em negociação).",
        }


def configure_stealth_mode(
    enabled: bool = True,
    proxy_url: str = "socks5://127.0.0.1:9050",
    dns_over_tor: bool = True,
) -> dict[str, Any]:
    """Configure and toggle the global stealth mode."""
    normalized = normalize_proxy_url(proxy_url, dns_over_tor=dns_over_tor)
    cfg = load_stealth_config()
    cfg["enabled"] = bool(enabled)
    cfg["proxy_url"] = normalized
    cfg["dns_over_tor"] = bool(dns_over_tor)
    save_stealth_config(cfg)

    status_str = "ATIVO" if enabled else "DESATIVADO"
    return {
        "status": "success",
        "stealth_mode": enabled,
        "proxy_url": normalized,
        "dns_over_tor": dns_over_tor,
        "message": f"Modo Stealth {status_str}! Tráfego configurado para o nó Onion {normalized}.",
    }


def is_stealth_active() -> bool:
    """Return whether stealth mode is currently activated."""
    cfg = load_stealth_config()
    return bool(cfg.get("enabled", False))


def get_active_proxy(force_tor: bool = False, custom_proxy: str | None = None) -> str | None:
    """Get active proxy URL if stealth is on or forced."""
    if custom_proxy and custom_proxy.strip():
        return normalize_proxy_url(custom_proxy.strip())

    cfg = load_stealth_config()
    if force_tor or cfg.get("enabled", False):
        proxy = cfg.get("proxy_url", "socks5://127.0.0.1:9050")
        return normalize_proxy_url(proxy, dns_over_tor=cfg.get("dns_over_tor", True))

    return None
