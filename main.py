#!/usr/bin/env python3
"""
main.py
-------
Orquestador principal de Asset Sentinel.

Coordina el ciclo completo de auditoria y monitoreo continuo:
  Recon -> Live Check -> Nuclei Scan -> Triage con Gemini -> Notificacion Telegram

Ejecutar con:
  python main.py

El proceso corre indefinidamente con intervalos configurados por SCAN_INTERVAL_HOURS.
"""

from __future__ import annotations

import logging
import shutil
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuracion del logging (debe hacerse ANTES de importar otros modulos)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("asset-sentinel.log", encoding="utf-8"),
    ],
)

logger = logging.getLogger("asset-sentinel")

# ---------------------------------------------------------------------------
# Importaciones del proyecto
# ---------------------------------------------------------------------------

from config.settings import get_settings
from core.scanner import (
    discover_subdomains,
    filter_live_hosts,
    run_nuclei_scan,
    update_nuclei_templates,
)
from core.triage import analyze_vulnerability
from core.notifier import (
    send_telegram_notification,
    send_scan_start_notification,
    send_scan_summary_notification,
    send_new_assets_notification,
)
from core.database import init_db, filter_new_hosts, is_new_finding

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

TARGETS_FILE = Path(__file__).parent / "config" / "targets.txt"
BANNER = r"""
 ___  __   __   ___  ___     __             __  ___  __  __  ___ 
|__  /__` /__` |__  |__     /__`  |__| /  \ |__) |  |__ |_ |__  |
|___ .__/ .__/ |___ |___    .__/  |  | \__/ |  \ |  |___ |__  |___|
                                                                     
         Asset Sentinel v1.0 | Auditoria y Monitoreo Continuo
"""


# ---------------------------------------------------------------------------
# Carga de objetivos
# ---------------------------------------------------------------------------

def load_targets() -> list[str]:
    """
    Carga la lista de dominios objetivo desde config/targets.txt.

    Lee el archivo linea por linea, ignora lineas vacias y comentarios
    (lineas que comienzan con '#').

    Returns:
        Lista de strings con los dominios/IPs en alcance.

    Raises:
        SystemExit: Si el archivo no existe o esta vacio.
    """
    if not TARGETS_FILE.exists():
        logger.error(
            "Archivo de objetivos no encontrado: %s\n"
            "  Crea el archivo y agrega un dominio por linea.",
            TARGETS_FILE,
        )
        sys.exit(1)

    targets: list[str] = []
    with open(TARGETS_FILE, encoding="utf-8-sig") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip().lstrip("\ufeff")
            if not line or line.startswith("#"):
                continue
            targets.append(line)
            logger.debug("  [%d] Objetivo cargado: %s", lineno, line)

    if not targets:
        logger.error(
            "El archivo %s esta vacio o solo contiene comentarios. "
            "Agrega al menos un dominio objetivo.",
            TARGETS_FILE,
        )
        sys.exit(1)

    logger.info("Objetivos cargados: %d dominios en alcance.", len(targets))
    return targets


# ---------------------------------------------------------------------------
# Verificacion de dependencias del sistema
# ---------------------------------------------------------------------------

def verify_system_dependencies() -> None:
    """
    Verifica que todos los binarios externos requeridos esten en PATH.
    Termina la ejecucion con un mensaje claro si alguno falta.
    """
    required = ["subfinder", "httpx", "nuclei"]
    missing = [b for b in required if shutil.which(b) is None]

    if missing:
        logger.error(
            "Binarios requeridos no encontrados en PATH: %s\n"
            "  Instalacion rapida (requiere Go 1.21+):\n"
            "    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
            "    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            "    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            "  Agrega $GOPATH/bin a tu PATH si es necesario.",
            ", ".join(missing),
        )
        sys.exit(1)

    logger.info("Verificacion de binarios OK: %s", ", ".join(required))


# ---------------------------------------------------------------------------
# Ciclo de escaneo para un objetivo
# ---------------------------------------------------------------------------

def run_scan_cycle(target: str) -> dict[str, Any]:
    """
    Ejecuta un ciclo completo de auditoria para un objetivo dado.

    Flujo:
        1. Notificacion de inicio
        2. Descubrimiento de subdominios (subfinder)
        3. Filtracion de hosts activos (httpx)
        4. Escaneo de vulnerabilidades (nuclei)
        5. Triaje con IA (Gemini) por cada hallazgo
        6. Notificacion de resumen y reportes individuales (Telegram)

    Args:
        target: Dominio o IP objetivo a escanear.

    Returns:
        Diccionario con estadisticas del ciclo: subdomains, live_hosts, findings.
    """
    logger.info("=" * 60)
    logger.info("INICIO DE CICLO | Objetivo: %s", target)
    logger.info("=" * 60)

    stats: dict[str, Any] = {
        "target": target,
        "subdomains": [],
        "live_hosts": [],
        "findings": [],
        "errors": [],
    }

    # --- Fase 1: Notificacion de inicio ---
    try:
        send_scan_start_notification(target)
    except Exception as e:
        logger.warning("No se pudo enviar notificacion de inicio: %s", e)

    # --- Fase 2: Reconocimiento de subdominios ---
    try:
        subdomains = discover_subdomains(target)
        stats["subdomains"] = subdomains
    except Exception as e:
        msg = f"Error en reconocimiento de subdominios para {target}: {e}"
        logger.error(msg)
        stats["errors"].append(msg)
        subdomains = []

    # Detectar activos nuevos (Delta) comparando con historial en SQLite
    if subdomains:
        new_subdomains, _ = filter_new_hosts(target, subdomains)
        if new_subdomains:
            logger.info("⚡ [Delta] %d NUEVO(S) subdominios detectados para %s!", len(new_subdomains), target)
            try:
                send_new_assets_notification(target, new_subdomains)
            except Exception as e:
                logger.warning("No se pudo enviar notificacion de nuevos activos: %s", e)

    # Agregar el dominio raiz a la lista de subdominios si no esta incluido
    all_hosts = list(set([target] + subdomains))

    # --- Fase 3: Filtracion de hosts activos ---
    try:
        live_hosts = filter_live_hosts(all_hosts)
        stats["live_hosts"] = live_hosts
    except Exception as e:
        msg = f"Error en filtracion de hosts para {target}: {e}"
        logger.error(msg)
        stats["errors"].append(msg)
        live_hosts = []

    if not live_hosts:
        logger.warning("No se encontraron hosts activos para %s. Saltando Nuclei.", target)
        send_scan_summary_notification(target, len(subdomains), 0, 0)
        return stats

    # --- Fase 4: Escaneo con Nuclei ---
    try:
        findings = run_nuclei_scan(live_hosts)
        stats["findings"] = findings
    except Exception as e:
        msg = f"Error en escaneo Nuclei para {target}: {e}"
        logger.error(msg)
        stats["errors"].append(msg)
        findings = []

    # --- Fase 5: Triaje y Notificacion por hallazgo ---
    for idx, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            logger.warning("Hallazgo #%d no es un diccionario valido (%s). Saltando.", idx, type(finding))
            continue

        template_id = finding.get("template-id", f"finding-{idx}")
        host = finding.get("host", "unknown")
        severity = finding.get("info", {}).get("severity", "unknown").upper()

        # Deduplicacion: Verificar si este hallazgo ya fue reportado previamente
        if not is_new_finding(target, finding):
            logger.info("Hallazgo ya reportado previamente (%s en %s). Omitiendo notificacion repetida.", template_id, host)
            continue

        logger.info(
            "[%d/%d] Analizando: %s | %s | Severidad: %s",
            idx,
            len(findings),
            template_id,
            host,
            severity,
        )

        # Triaje con Gemini
        try:
            report_md = analyze_vulnerability(finding)
        except Exception as e:
            logger.error("Error en triaje de '%s': %s", template_id, e)
            report_md = f"*Error al generar reporte para `{template_id}`*\n`{e}`"

        # Construir mensaje de Telegram
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(severity, "⚪")

        header = (
            f"{severity_emoji} *HALLAZGO {severity} #{idx}*\n"
            f"🎯 *Objetivo:* `{target}`\n"
            f"🌐 *Host:* `{host}`\n"
            f"📋 *Template:* `{template_id}`\n\n"
            f"{'─' * 30}\n\n"
        )

        notification_text = header + report_md

        try:
            send_telegram_notification(notification_text)
            time.sleep(1)  # Rate limiting: max 1 mensaje/segundo
        except Exception as e:
            logger.error("Error enviando notificacion para '%s': %s", template_id, e)

    # --- Fase 6: Resumen final ---
    try:
        send_scan_summary_notification(
            target=target,
            subdomains_count=len(stats["subdomains"]),
            live_hosts_count=len(stats["live_hosts"]),
            findings_count=len(stats["findings"]),
        )
    except Exception as e:
        logger.warning("No se pudo enviar resumen: %s", e)

    logger.info(
        "FIN DE CICLO | %s | Subdominios: %d | Hosts activos: %d | Hallazgos: %d",
        target,
        len(stats["subdomains"]),
        len(stats["live_hosts"]),
        len(stats["findings"]),
    )
    return stats


# ---------------------------------------------------------------------------
# Bucle principal
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Punto de entrada principal del orquestador.

    Ejecuta ciclos de escaneo indefinidamente sobre todos los objetivos
    configurados, respetando el intervalo definido por SCAN_INTERVAL_HOURS.
    Maneja interrupciones de teclado (Ctrl+C) de forma limpia.
    """
    print(BANNER)
    logger.info("Asset Sentinel iniciando...")

    init_db()
    settings = get_settings()
    verify_system_dependencies()
    targets = load_targets()

    logger.info(
        "Configuracion: %d objetivos | Intervalo: %.1fh | Severidades: %s",
        len(targets),
        settings.SCAN_INTERVAL_HOURS,
        settings.NUCLEI_SEVERITY,
    )
    if settings.HACKERONE_USERNAME:
        logger.info("Identificacion Safe Harbor: 'X-hackerone: %s' activada en escaneos.", settings.HACKERONE_USERNAME)

    cycle_number = 0

    try:
        while True:
            cycle_number += 1
            targets = load_targets()
            logger.info("*** INICIANDO CICLO GLOBAL #%d (%d objetivos) ***", cycle_number, len(targets))

            # Auto-actualizar plantillas de Nuclei con los CVEs mas recientes
            update_nuclei_templates()

            cycle_start = time.time()

            all_stats: list[dict[str, Any]] = []
            for target in targets:
                try:
                    stats = run_scan_cycle(target)
                    all_stats.append(stats)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logger.exception(
                        "Error no controlado en ciclo para '%s': %s", target, e
                    )

            # Calcular tiempo del ciclo completo
            elapsed = time.time() - cycle_start
            total_findings = sum(len(s.get("findings", [])) for s in all_stats)

            logger.info(
                "*** CICLO #%d COMPLETADO | Tiempo: %.1fs | "
                "Objetivos: %d | Hallazgos totales: %d ***",
                cycle_number,
                elapsed,
                len(targets),
                total_findings,
            )

            # Calcular tiempo de espera hasta el proximo ciclo
            sleep_seconds = settings.SCAN_INTERVAL_HOURS * 3600
            next_run = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(time.time() + sleep_seconds),
            )
            logger.info(
                "Proximo ciclo en %.1f horas (%s). Esperando...",
                settings.SCAN_INTERVAL_HOURS,
                next_run,
            )

            time.sleep(sleep_seconds)

    except KeyboardInterrupt:
        logger.info("\nAsset Sentinel detenido manualmente (Ctrl+C). Hasta luego.")
        sys.exit(0)


if __name__ == "__main__":
    main()
