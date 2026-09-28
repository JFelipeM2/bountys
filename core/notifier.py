"""
core/notifier.py
----------------
Modulo de notificaciones via webhook de Telegram.
Envia alertas de seguridad con manejo de truncado,
reintentos y rate limiting para evitar bloqueos de la API.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import get_settings

logger = logging.getLogger(__name__)

# Limite de Telegram para mensajes de texto (en caracteres)
_TELEGRAM_MAX_CHARS = 4096
# Reservamos espacio para el aviso de truncado
_TRUNCATE_SUFFIX = "\n\n⚠️ _[Mensaje truncado. Revisa los logs para el reporte completo.]_"
_EFFECTIVE_MAX_CHARS = _TELEGRAM_MAX_CHARS - len(_TRUNCATE_SUFFIX)


# ---------------------------------------------------------------------------
# Sesion HTTP con reintentos
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    """
    Crea una sesion requests con politica de reintentos automaticos.

    Reintentos configurados para:
    - Errores de red (ConnectionError, Timeout)
    - Codigos HTTP 429 (Rate Limit), 500, 502, 503, 504
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=2.0,              # Espera: 2s, 4s, 8s entre reintentos
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.timeout = (10, 30)           # (connect_timeout, read_timeout)
    return session


_session: requests.Session = _build_session()


# ---------------------------------------------------------------------------
# Funcion principal de notificacion
# ---------------------------------------------------------------------------

def send_telegram_notification(
    text: str,
    parse_mode: str = "Markdown",
    disable_preview: bool = True,
) -> bool:
    """
    Envia un mensaje de texto al chat de Telegram configurado.

    Si el texto supera el limite de 4096 caracteres de Telegram, lo trunca
    automaticamente y agrega un aviso al final.

    Args:
        text:            Texto del mensaje (soporta Markdown o HTML segun parse_mode).
        parse_mode:      Modo de formato: 'Markdown', 'MarkdownV2' o 'HTML'.
                         Por defecto 'Markdown' (compatible con formato basico).
        disable_preview: Si True, desactiva el preview de enlaces. Default True.

    Returns:
        True si el mensaje fue enviado exitosamente, False en caso contrario.
    """
    settings = get_settings()
    api_url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"

    # Truncar si excede el limite
    if len(text) > _EFFECTIVE_MAX_CHARS:
        logger.warning(
            "[Notifier] Mensaje truncado de %d a %d caracteres.",
            len(text),
            _EFFECTIVE_MAX_CHARS,
        )
        text = text[:_EFFECTIVE_MAX_CHARS] + _TRUNCATE_SUFFIX

    payload: dict[str, Any] = {
        "chat_id": settings.TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": disable_preview,
    }

    try:
        response = _session.post(api_url, json=payload)
        response.raise_for_status()
        data = response.json()

        if not data.get("ok"):
            logger.error(
                "[Notifier] Telegram respondio con error: %s",
                data.get("description", "sin descripcion"),
            )
            return False

        logger.info("[Notifier] Notificacion enviada exitosamente (message_id=%s).",
                    data.get("result", {}).get("message_id", "?"))
        return True

    except requests.exceptions.Timeout:
        logger.error("[Notifier] Timeout al conectar con la API de Telegram.")
        return False
    except requests.exceptions.ConnectionError as e:
        logger.error("[Notifier] Error de conexion con Telegram: %s", e)
        return False
    except requests.exceptions.HTTPError as e:
        logger.error("[Notifier] Error HTTP de Telegram: %s | Body: %s",
                     e, e.response.text[:300] if e.response else "N/A")
        return False
    except Exception as e:
        logger.exception("[Notifier] Error inesperado al enviar notificacion: %s", e)
        return False


def send_scan_start_notification(target: str) -> bool:
    """
    Envia una notificacion de inicio de ciclo de escaneo.

    Args:
        target: Dominio o IP objetivo del escaneo.

    Returns:
        True si se envio exitosamente.
    """
    message = (
        f"🔍 *Asset Sentinel - Escaneo Iniciado*\n\n"
        f"🎯 *Objetivo:* `{target}`\n"
        f"⏰ *Hora:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n"
        f"_Iniciando fase de reconocimiento..._"
    )
    return send_telegram_notification(message)


def send_scan_summary_notification(
    target: str,
    subdomains_count: int,
    live_hosts_count: int,
    findings_count: int,
) -> bool:
    """
    Envia un resumen del ciclo de escaneo completado.

    Args:
        target:            Dominio objetivo.
        subdomains_count:  Numero de subdominios descubiertos.
        live_hosts_count:  Numero de hosts activos encontrados.
        findings_count:    Numero de vulnerabilidades detectadas.

    Returns:
        True si se envio exitosamente.
    """
    status_emoji = "🚨" if findings_count > 0 else "✅"
    message = (
        f"{status_emoji} *Asset Sentinel - Resumen de Escaneo*\n\n"
        f"🎯 *Objetivo:* `{target}`\n"
        f"🌐 *Subdominios:* {subdomains_count}\n"
        f"🟢 *Hosts Activos:* {live_hosts_count}\n"
        f"⚠️ *Vulnerabilidades:* {findings_count}\n"
        f"⏰ *Hora:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
    )
    return send_telegram_notification(message)


def send_new_assets_notification(target: str, new_hosts: list[str]) -> bool:
    """
    Envia una alerta cuando se detectan nuevos subdominios que no existian previamente.
    """
    if not new_hosts:
        return False
    sample = new_hosts[:8]
    hosts_text = "\n".join(f"• `{h}`" for h in sample)
    if len(new_hosts) > 8:
        hosts_text += f"\n_... y {len(new_hosts) - 8} subdominios mas._"

    message = (
        f"⚡ *¡NUEVOS ACTIVOS DESCUBIERTOS!*\n\n"
        f"🎯 *Objetivo:* `{target}`\n"
        f"🆕 *Cantidad:* {len(new_hosts)} nuevo(s)\n\n"
        f"{hosts_text}\n\n"
        f"⏰ *Hora:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
        f"_Analizando vulnerabilidades prioritarias..._"
    )
    return send_telegram_notification(message)
