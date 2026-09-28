"""
core/database.py
----------------
Gestion de persistencia local con SQLite para:
1. Seguimiento de subdominios conocidos (deteccion de nuevos activos / delta).
2. Deduplicacion de hallazgos de seguridad para no repetir alertas.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parents[1] / "sentinel.db"


def get_db_connection() -> sqlite3.Connection:
    """Crea o retorna conexion a la base de datos SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Inicializa las tablas necesarias si no existen."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Tabla de subdominios descubiertos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovered_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain TEXT NOT NULL,
                host TEXT NOT NULL UNIQUE,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL
            )
        """)
        
        # Tabla de vulnerabilidades reportadas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reported_findings (
                finding_hash TEXT PRIMARY KEY,
                target_domain TEXT NOT NULL,
                template_id TEXT NOT NULL,
                host TEXT NOT NULL,
                severity TEXT NOT NULL,
                first_reported TIMESTAMP NOT NULL
            )
        """)
        
        conn.commit()
    logger.debug("[Database] Tablas SQLite inicializadas correctamente en %s.", DB_PATH)


def filter_new_hosts(target_domain: str, hosts: list[str]) -> tuple[list[str], list[str]]:
    """
    Compara una lista de hosts con los registros historicos de la base de datos.

    Args:
        target_domain: El dominio base (ej. 'expedia.com').
        hosts: Lista actual de subdominios descubiertos.

    Returns:
        Tupla con (hosts_nuevos, todos_los_hosts).
    """
    if not hosts:
        return [], []

    now = datetime.utcnow().isoformat()
    new_hosts: list[str] = []

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for host in hosts:
            host_clean = host.strip().lower()
            cursor.execute("SELECT id FROM discovered_hosts WHERE host = ?", (host_clean,))
            row = cursor.fetchone()
            if row is None:
                new_hosts.append(host_clean)
                cursor.execute(
                    "INSERT INTO discovered_hosts (target_domain, host, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                    (target_domain, host_clean, now, now),
                )
            else:
                cursor.execute(
                    "UPDATE discovered_hosts SET last_seen = ? WHERE id = ?",
                    (now, row["id"]),
                )
        conn.commit()

    return new_hosts, hosts


def is_new_finding(target_domain: str, finding: dict[str, Any]) -> bool:
    """
    Calcula un hash unico del hallazgo (host + template_id + matcher_name).
    Retorna True si el hallazgo nunca ha sido reportado previamente, y lo registra.
    """
    template_id = str(finding.get("template-id", ""))
    host = str(finding.get("host", ""))
    matcher_name = str(finding.get("matcher-name", ""))
    severity = str(finding.get("info", {}).get("severity", "unknown")).upper()

    fingerprint = f"{target_domain}|{host}|{template_id}|{matcher_name}"
    finding_hash = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    now = datetime.utcnow().isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT finding_hash FROM reported_findings WHERE finding_hash = ?", (finding_hash,))
        if cursor.fetchone() is not None:
            # Ya fue reportado anteriormente
            return False

        # Registrar nuevo hallazgo
        cursor.execute(
            """
            INSERT INTO reported_findings (finding_hash, target_domain, template_id, host, severity, first_reported)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (finding_hash, target_domain, template_id, host, severity, now),
        )
        conn.commit()

    return True
