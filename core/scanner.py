"""
core/scanner.py
---------------
Modulo ejecutor de herramientas de reconocimiento CLI.
Orquesta subfinder, httpx y nuclei mediante subprocess con
manejo de excepciones, timeouts y logging estructurado.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from config.settings import get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _assert_binary(name: str) -> None:
    """Falla rapidamente si un binario requerido no esta en PATH."""
    if shutil.which(name) is None:
        logger.error("Binario '%s' no encontrado en PATH. Abortando.", name)
        sys.exit(1)


def _run(cmd: list[str], input_data: str | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    """
    Wrapper seguro sobre subprocess.run.

    Args:
        cmd:        Lista de argumentos del comando.
        input_data: Texto a pasar por stdin (opcional).
        timeout:    Segundos antes de forzar terminacion.

    Returns:
        Objeto CompletedProcess con stdout/stderr capturados.

    Raises:
        RuntimeError: Si el proceso falla o excede el timeout.
    """
    settings = get_settings()
    effective_timeout = timeout or settings.SUBPROCESS_TIMEOUT

    logger.debug("Ejecutando: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=effective_timeout,
        )
        if result.returncode not in (0, 1):
            # Codigo 1 es aceptable en algunas herramientas (sin resultados)
            logger.warning(
                "Comando '%s' termino con codigo %d. Stderr: %s",
                cmd[0],
                result.returncode,
                result.stderr[:500],
            )
        return result
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Timeout de {effective_timeout}s superado al ejecutar: {' '.join(cmd)}"
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"Comando '{cmd[0]}' no encontrado. Verifica que este instalado en PATH."
        )


# ---------------------------------------------------------------------------
# Funciones publicas del modulo
# ---------------------------------------------------------------------------

def update_nuclei_templates() -> bool:
    """
    Actualiza las plantillas comunitarias de Nuclei ejecutando 'nuclei -ut'.
    """
    _assert_binary("nuclei")
    logger.info("[Nuclei] Verificando actualizaciones de plantillas comunitarias...")
    try:
        _run(["nuclei", "-ut", "-silent"], timeout=120)
        logger.info("[Nuclei] Plantillas de Nuclei al dia.")
        return True
    except Exception as e:
        logger.warning("[Nuclei] No se pudieron actualizar las plantillas: %s", e)
        return False


def discover_subdomains(target_domain: str) -> list[str]:
    """
    Descubre subdominios de un dominio objetivo usando subfinder.

    Args:
        target_domain: Dominio raiz a enumerar (ej: 'example.com').

    Returns:
        Lista de subdominios descubiertos (puede estar vacia).
    """
    _assert_binary("subfinder")
    logger.info("[Recon] Iniciando descubrimiento de subdominios para: %s", target_domain)

    cmd = ["subfinder", "-d", target_domain, "-silent"]
    result = _run(cmd)

    subdomains: list[str] = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    logger.info("[Recon] %d subdominios descubiertos para %s.", len(subdomains), target_domain)
    return subdomains


def filter_live_hosts(hosts: list[str]) -> list[str]:
    """
    Filtra hosts activos usando httpx verificando codigos de respuesta HTTP.

    Args:
        hosts: Lista de hostnames o URLs a verificar.

    Returns:
        Lista de URLs de hosts que respondieron con codigos validos.
    """
    if not hosts:
        logger.warning("[LiveCheck] Lista de hosts vacia. Saltando filtracion.")
        return []

    _assert_binary("httpx")
    settings = get_settings()
    logger.info("[LiveCheck] Verificando %d hosts con httpx...", len(hosts))

    # httpx acepta stdin como lista de hosts
    stdin_data = "\n".join(hosts)
    cmd = [
        "httpx",
        "-silent",
        "-mc", settings.HTTPX_STATUS_CODES,
        "-rl", "100",
    ]
    if settings.HACKERONE_USERNAME:
        cmd.extend(["-H", f"X-hackerone: {settings.HACKERONE_USERNAME}"])

    result = _run(cmd, input_data=stdin_data)

    live_hosts: list[str] = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    logger.info("[LiveCheck] %d hosts activos encontrados.", len(live_hosts))
    return live_hosts


def run_nuclei_scan(live_hosts: list[str]) -> list[dict[str, Any]]:
    """
    Ejecuta un escaneo de vulnerabilidades con nuclei sobre hosts activos.

    Nuclei escribe sus hallazgos en formato JSON a un archivo temporal
    que luego se parsea y retorna como lista de diccionarios.

    Args:
        live_hosts: Lista de URLs activas a escanear.

    Returns:
        Lista de hallazgos como diccionarios. Cada dict contiene los campos
        originales del JSON de nuclei (template-id, severity, host, etc).
    """
    if not live_hosts:
        logger.warning("[Nuclei] Lista de hosts vacia. Saltando escaneo.")
        return []

    _assert_binary("nuclei")
    settings = get_settings()
    logger.info("[Nuclei] Iniciando escaneo sobre %d hosts...", len(live_hosts))

    # Usamos archivo temporal para la exportacion JSON y stdin para los targets
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
        prefix="nuclei_findings_",
    ) as tmp_file:
        output_path = Path(tmp_file.name)

    try:
        stdin_data = "\n".join(live_hosts)
        cmd = [
            "nuclei",
            "-severity", settings.NUCLEI_SEVERITY,
            "-json-export", str(output_path),
            "-silent",
            "-no-color",
            "-rl", "100",
        ]
        if settings.HACKERONE_USERNAME:
            cmd.extend(["-H", f"X-hackerone: {settings.HACKERONE_USERNAME}"])

        _run(cmd, input_data=stdin_data)

        # Parsear el archivo JSON de resultados
        findings: list[dict[str, Any]] = []
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path, encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
                if content:
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, list):
                            for item in parsed:
                                if isinstance(item, dict):
                                    findings.append(item)
                        elif isinstance(parsed, dict):
                            findings.append(parsed)
                    except json.JSONDecodeError:
                        # Fallback en caso de formato JSONL (un JSON por linea)
                        for line in content.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                item = json.loads(line)
                                if isinstance(item, dict):
                                    findings.append(item)
                                elif isinstance(item, list):
                                    findings.extend([x for x in item if isinstance(x, dict)])
                            except json.JSONDecodeError as e:
                                logger.warning("No se pudo parsear linea de nuclei: %s | Error: %s", line[:100], e)

        logger.info("[Nuclei] %d hallazgos encontrados.", len(findings))
        return findings

    finally:
        # Limpiar archivo temporal
        if output_path.exists():
            output_path.unlink(missing_ok=True)
