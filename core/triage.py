"""
core/triage.py
--------------
Modulo de inteligencia artificial para triaje de vulnerabilidades.
Usa el SDK oficial google-genai para interactuar con Gemini 2.5 Flash
y generar reportes profesionales de cada hallazgo de seguridad.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from google import genai
from google.genai import types

from config.settings import get_settings

logger = logging.getLogger(__name__)

# Modelo de Gemini a utilizar
_GEMINI_MODEL = "gemini-3.8-flash"

# Prompt base del sistema para el analista de seguridad
_SYSTEM_PROMPT = """Eres un experto en ciberseguridad ofensiva y defensiva con mas de 15 anos de
experiencia en Bug Bounty, pentesting y respuesta a incidentes. Tu tarea es analizar
hallazgos de seguridad generados por la herramienta Nuclei y redactar reportes tecnicos
profesionales, claros y accionables en formato Markdown.

Reglas estrictas:
- Basa tu analisis UNICAMENTE en los datos del hallazgo proporcionado.
- Si no tienes suficiente contexto para un campo, indicalo explicitamente.
- No inventes CVEs ni scores CVSS que no esten en los datos.
- El reporte debe ser util para un equipo de seguridad y para un desarrollador.
- Usa Markdown valido y bien estructurado.
- Responde SIEMPRE en espanol."""

# Template del prompt de usuario
_USER_PROMPT_TEMPLATE = """Analiza el siguiente hallazgo de seguridad detectado por Nuclei y genera
un reporte profesional completo.

## Datos del hallazgo (JSON):
```json
{vuln_json}
```

## Reporte requerido (usa exactamente estas secciones):

### Resumen Ejecutivo
Explica en 2-3 oraciones que se encontro, donde y que riesgo representa para el negocio.

### Severidad y Clasificacion
- **Severidad Nuclei**: [extraer del campo 'info.severity']
- **Puntuacion CVSS**: [si esta disponible en los datos, mostrarla; si no, estimar basado en el tipo de vulnerabilidad]
- **Vector CVSS**: [si aplica]
- **CWE / CVE**: [si estan disponibles en los datos]

### Descripcion Tecnica
Explica el mecanismo tecnico de la vulnerabilidad de forma detallada.

### Pasos de Reproduccion
Proporciona los pasos exactos y reproducibles para verificar el hallazgo, incluyendo
comandos curl o URLs de ejemplo basados en los datos disponibles.

### Impacto Potencial
Describe los escenarios de ataque posibles si esta vulnerabilidad fuera explotada.

### Remediacion Recomendada
Proporciona pasos concretos y priorizados para remediar la vulnerabilidad.

### Referencias
Lista recursos relevantes (OWASP, CVE, documentacion oficial) relacionados con este tipo de vulnerabilidad."""


# ---------------------------------------------------------------------------
# Cliente Gemini (singleton)
# ---------------------------------------------------------------------------

_gemini_client: genai.Client | None = None


def _get_client() -> genai.Client:
    """Retorna el cliente Gemini inicializado (singleton)."""
    global _gemini_client
    if _gemini_client is None:
        settings = get_settings()
        _gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)
        logger.debug("Cliente Gemini inicializado con modelo %s.", _GEMINI_MODEL)
    return _gemini_client


# ---------------------------------------------------------------------------
# Funcion principal de triaje
# ---------------------------------------------------------------------------

def analyze_vulnerability(vuln_data: dict[str, Any]) -> str:
    """
    Analiza un hallazgo de vulnerabilidad usando Gemini y genera un reporte.

    Toma el diccionario crudo de un hallazgo de Nuclei, lo serializa a JSON
    y lo envia a Gemini con un prompt estructurado para obtener un reporte
    profesional en Markdown.

    Args:
        vuln_data: Diccionario con los datos del hallazgo tal como los
                   retorna nuclei en formato JSON (template-id, severity,
                   host, matched-at, info, etc).

    Returns:
        String en formato Markdown con el reporte completo del hallazgo.
        En caso de error con la API, retorna un mensaje de error descriptivo.
    """
    client = _get_client()

    # Extraer identificadores para el log
    template_id = vuln_data.get("template-id", "unknown")
    host = vuln_data.get("host", "unknown")
    severity = vuln_data.get("info", {}).get("severity", "unknown")
    logger.info(
        "[Triage] Analizando hallazgo: %s | Host: %s | Severidad: %s",
        template_id,
        host,
        severity,
    )

    # Serializar el hallazgo a JSON formateado para el prompt
    try:
        vuln_json = json.dumps(vuln_data, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        logger.error("Error serializando hallazgo a JSON: %s", e)
        vuln_json = str(vuln_data)

    user_prompt = _USER_PROMPT_TEMPLATE.format(vuln_json=vuln_json)

    try:
        response = client.models.generate_content(
            model=_GEMINI_MODEL,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.2,        # Baja temperatura para respuestas mas precisas
                max_output_tokens=4096,
            ),
        )

        report = response.text
        if not report:
            raise ValueError("Gemini retorno una respuesta vacia.")

        logger.info("[Triage] Reporte generado exitosamente para '%s'.", template_id)
        return report

    except Exception as exc:
        error_msg = (
            f"**[ERROR DE TRIAJE]** No se pudo generar el reporte para "
            f"`{template_id}` en `{host}`.\n\n"
            f"**Error:** `{exc}`\n\n"
            f"**Datos originales del hallazgo:**\n```json\n{vuln_json[:1000]}\n```"
        )
        logger.error(
            "[Triage] Error al llamar a Gemini API para '%s': %s",
            template_id,
            exc,
        )
        return error_msg
