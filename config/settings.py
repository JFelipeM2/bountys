"""
config/settings.py
------------------
Carga y valida las variables de entorno del proyecto asset-sentinel
usando pydantic-settings para tipado estatico y validacion automatica.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import ClassVar

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuracion central del proyecto.

    Lee automaticamente desde el archivo .env ubicado en la raiz del proyecto,
    y tambien acepta variables de entorno del sistema operativo (mayor prioridad).
    """

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[1] / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Credenciales de APIs ---
    GEMINI_API_KEY: str = Field(
        ...,
        description="Clave de API de Google Gemini (obligatoria).",
        min_length=10,
    )
    TELEGRAM_BOT_TOKEN: str = Field(
        ...,
        description="Token del bot de Telegram en formato '1234567890:ABC...'.",
        min_length=10,
    )
    TELEGRAM_CHAT_ID: str = Field(
        ...,
        description="Chat ID o Channel ID de Telegram donde se envian alertas.",
    )

    # --- Identificacion HackerOne (Safe Harbor) ---
    HACKERONE_USERNAME: str | None = Field(
        default=None,
        description="Usuario de HackerOne para cabecera 'X-hackerone: <user>' en herramientas.",
    )

    # --- Parametros de escaneo ---
    SCAN_INTERVAL_HOURS: float = Field(
        default=6.0,
        description="Intervalo en horas entre ciclos de escaneo completo.",
        gt=0,
        le=168,
    )
    NUCLEI_SEVERITY: str = Field(
        default="medium,high,critical",
        description="Severidades de Nuclei a incluir (separadas por coma).",
    )
    HTTPX_STATUS_CODES: str = Field(
        default="200,301,302,403",
        description="Codigos HTTP validos para filtrar hosts vivos.",
    )
    SUBPROCESS_TIMEOUT: int = Field(
        default=300,
        description="Timeout en segundos para cada subproceso externo.",
        gt=0,
    )

    # --- Binarios externos requeridos ---
    REQUIRED_BINARIES: ClassVar[list[str]] = ["subfinder", "httpx", "nuclei"]

    @field_validator("TELEGRAM_BOT_TOKEN")
    @classmethod
    def validate_telegram_token(cls, v: str) -> str:
        """Verifica formato basico token Telegram: '<id>:<hash>'."""
        if ":" not in v:
            raise ValueError(
                "TELEGRAM_BOT_TOKEN debe tener el formato '<bot_id>:<hash>'."
            )
        return v.strip()

    @field_validator("GEMINI_API_KEY", "TELEGRAM_CHAT_ID")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        """Elimina espacios en blanco accidentales."""
        return v.strip()

    @model_validator(mode="after")
    def check_binaries_in_path(self) -> "Settings":
        """
        Verifica que los binarios externos necesarios esten disponibles en PATH.
        Emite advertencias para permitir entornos de prueba sin detener la app.
        """
        missing: list[str] = [
            binary
            for binary in self.REQUIRED_BINARIES
            if shutil.which(binary) is None
        ]
        if missing:
            print(
                f"[ADVERTENCIA] Binarios no encontrados en PATH: {', '.join(missing)}\n"
                f"  - subfinder : go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
                f"  - httpx     : go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                f"  - nuclei    : go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                file=sys.stderr,
            )
        return self


_settings: Settings | None = None


def get_settings() -> Settings:
    """
    Retorna la instancia singleton de Settings.
    Lanza un error descriptivo si faltan variables obligatorias.
    """
    global _settings
    if _settings is None:
        try:
            _settings = Settings()
        except Exception as exc:
            print(
                f"[ERROR FATAL] Fallo al cargar configuracion:\n  {exc}\n"
                f"  Copia '.env.example' como '.env' y rellena los valores requeridos.",
                file=sys.stderr,
            )
            sys.exit(1)
    return _settings
