# Asset Sentinel

> **Herramienta de auditoria y monitoreo continuo de activos web con triaje de IA.**  
> Integra subfinder, httpx, nuclei y Gemini AI para descubrir, verificar y reportar vulnerabilidades automaticamente.

---

## Caracteristicas

- **Reconocimiento automatico** de subdominios con `subfinder`
- **Verificacion de hosts activos** con `httpx`
- **Escaneo de vulnerabilidades** con `nuclei` (medium/high/critical)
- **Triaje inteligente** con Google Gemini 2.5 Flash: genera reportes profesionales en Markdown
- **Alertas en tiempo real** por Telegram con manejo de truncado
- **Ciclos continuos** configurables por horas
- **Tipado estatico** completo con type hints y validacion con Pydantic

---

## Requisitos del Sistema

### Python
- Python 3.11+
- pip

### Binarios externos (requieren Go 1.21+)

```bash
# Instalar Go si no lo tienes: https://go.dev/dl/
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Asegurate de que $GOPATH/bin este en tu PATH:
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## Instalacion

### 1. Clonar / Descargar el proyecto

```bash
cd /opt
git clone <tu-repo> asset-sentinel
cd asset-sentinel
```

### 2. Crear entorno virtual e instalar dependencias

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

### 3. Configurar variables de entorno

```bash
cp .env.example .env
nano .env   # Edita con tus credenciales reales
```

Variables requeridas en `.env`:

| Variable             | Descripcion                              | Ejemplo                        |
|----------------------|------------------------------------------|--------------------------------|
| `GEMINI_API_KEY`     | API Key de Google AI Studio              | `AIzaSy...`                    |
| `TELEGRAM_BOT_TOKEN` | Token del bot de Telegram                | `1234567890:ABC...`            |
| `TELEGRAM_CHAT_ID`   | Chat ID donde se envian las alertas      | `-100123456789` o `123456789`  |
| `SCAN_INTERVAL_HOURS`| Horas entre ciclos (default: 6)          | `6`                            |

### 4. Agregar objetivos en alcance

```bash
nano config/targets.txt
```

Formato (un dominio por linea):
```
# Comentarios con #
example.com
another-target.io
```

> ⚠️ **IMPORTANTE:** Solo incluye dominios para los que tengas autorizacion expresa de escaneo.

---

## Ejecucion

### Modo desarrollo (interactivo)

```bash
python main.py
```

### Modo produccion con systemd (recomendado para VPS)

Crea el archivo de servicio:

```bash
sudo nano /etc/systemd/system/asset-sentinel.service
```

Contenido:

```ini
[Unit]
Description=Asset Sentinel - Monitoreo Continuo de Activos
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/asset-sentinel
ExecStart=/opt/asset-sentinel/.venv/bin/python main.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
EnvironmentFile=/opt/asset-sentinel/.env

[Install]
WantedBy=multi-user.target
```

Activar el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable asset-sentinel
sudo systemctl start asset-sentinel
sudo systemctl status asset-sentinel

# Ver logs en tiempo real:
sudo journalctl -u asset-sentinel -f
```

### Modo produccion con screen (alternativa simple)

```bash
screen -S sentinel
python main.py
# Ctrl+A, D para desconectar sin matar el proceso
# screen -r sentinel para volver a conectar
```

---

## Estructura del Proyecto

```
asset-sentinel/
├── config/
│   ├── settings.py      # Carga y valida variables de entorno (pydantic-settings)
│   └── targets.txt      # Lista de dominios en alcance (uno por linea)
├── core/
│   ├── __init__.py      # Exportaciones del paquete
│   ├── scanner.py       # Ejecutor de subfinder, httpx, nuclei via subprocess
│   ├── triage.py        # Integracion con Gemini 2.5 Flash para analisis de vulns
│   └── notifier.py      # Notificaciones a Telegram con reintentos y truncado
├── .env                 # Variables secretas (NO commitear)
├── .env.example         # Plantilla de variables (commiteable)
├── requirements.txt     # Dependencias Python
├── main.py              # Orquestador del ciclo de escaneo
└── README.md            # Esta documentacion
```

---

## Flujo de Ejecucion

```
main.py
  |
  ├─ load_targets()          <- config/targets.txt
  |
  └─ LOOP (cada SCAN_INTERVAL_HOURS horas):
       |
       ├─ Para cada target:
       |    |
       |    ├─ [1] send_scan_start_notification()     -> Telegram
       |    ├─ [2] discover_subdomains(target)         -> subfinder
       |    ├─ [3] filter_live_hosts(subdomains)        -> httpx
       |    ├─ [4] run_nuclei_scan(live_hosts)          -> nuclei
       |    ├─ [5] Para cada hallazgo:
       |    |       ├─ analyze_vulnerability(finding)   -> Gemini 2.5 Flash
       |    |       └─ send_telegram_notification(report)
       |    └─ [6] send_scan_summary_notification()    -> Telegram
       |
       └─ time.sleep(SCAN_INTERVAL_HOURS * 3600)
```

---

## Logs

Los logs se escriben en:
- **stdout**: Consola / journald
- **asset-sentinel.log**: Archivo local en la raiz del proyecto

Nivel de log por defecto: `INFO`. Para debug:

```bash
# Cambiar nivel en main.py:
logging.basicConfig(level=logging.DEBUG, ...)
```

---

## Seguridad

- El archivo `.env` contiene credenciales sensibles. **Nunca lo subas a git.**
- Agrega `.env` a tu `.gitignore`.
- Ejecuta el servicio con un usuario de bajos privilegios (sin root).
- Solo escanea dominios con autorizacion expresa (Bug Bounty programs, tus propios activos).

---

## Licencia

MIT License. Uso bajo tu propia responsabilidad y siempre dentro del marco legal aplicable.
