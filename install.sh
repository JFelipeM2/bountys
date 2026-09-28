#!/usr/bin/env bash
# ==============================================================================
#  Asset Sentinel - Script de Instalacion Automatica para Fedora Linux
#  Uso: bash install.sh
#  Requiere: Fedora 38+ | Usuario con sudo
# ==============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  echo " ╔══════════════════════════════════════════════════════╗"
  echo " ║          ASSET SENTINEL - AUTO INSTALLER             ║"
  echo " ║          Fedora Linux Edition  v1.0                  ║"
  echo " ╚══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
step()    { echo -e "\n${BOLD}${YELLOW}══ $* ${RESET}"; }

# ── Variables de instalacion ──────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/asset-sentinel}"
SERVICE_USER="${SERVICE_USER:-sentinel}"
GO_VERSION="1.23.0"
VENV_DIR="$INSTALL_DIR/.venv"
SERVICE_FILE="/etc/systemd/system/asset-sentinel.service"
LOG_FILE="/tmp/asset-sentinel-install.log"

# Redirigir errores al log manteniendo salida en pantalla
exec 2> >(tee -a "$LOG_FILE" >&2)

# ── Verificaciones previas ────────────────────────────────────────────────────
check_root() {
  if [[ "$EUID" -eq 0 ]]; then
    warn "Estas ejecutando como root. Se recomienda un usuario normal con sudo."
    warn "Presiona Ctrl+C para cancelar o ENTER para continuar..."
    read -r
  fi
}

check_fedora() {
  if [[ ! -f /etc/fedora-release ]]; then
    warn "Este script esta optimizado para Fedora Linux."
    warn "En otras distros es posible que necesites adaptar los comandos de paquetes."
    warn "Presiona ENTER para continuar de todas formas o Ctrl+C para salir..."
    read -r
  else
    FEDORA_VERSION=$(rpm -E %fedora)
    info "Fedora $FEDORA_VERSION detectado."
  fi
}

check_internet() {
  info "Verificando conexion a internet..."
  if ! curl -s --max-time 5 https://google.com > /dev/null; then
    error "Sin conexion a internet. Verifica tu red e intenta de nuevo."
  fi
  success "Conexion a internet OK."
}

# ── Paso 1: Dependencias del sistema ─────────────────────────────────────────
install_system_deps() {
  step "Paso 1/6: Instalando dependencias del sistema"

  # No hacemos 'dnf update' completo — puede tardar mucho y no es necesario.
  # Solo sincronizamos metadatos de los repos.
  info "Sincronizando metadatos de repositorios (makecache)..."
  sudo dnf makecache 2>&1 | tail -3

  info "Instalando paquetes base (puede tardar 1-2 min)..."
  PACKAGES=(git curl wget tar python3 python3-pip python3-devel gcc make)

  for PKG in "${PACKAGES[@]}"; do
    if rpm -q "$PKG" &>/dev/null; then
      info "  $PKG ya instalado, saltando."
    else
      info "  Instalando $PKG..."
      sudo dnf install -y --skip-broken "$PKG" >> "$LOG_FILE" 2>&1 && \
        success "  $PKG OK." || warn "  $PKG fallo (no critico)."
    fi
  done

  # python3-venv puede llamarse python3-virtualenv en Fedora
  if ! python3 -m venv --help &>/dev/null; then
    info "Instalando soporte de venv..."
    sudo dnf install -y python3-virtualenv >> "$LOG_FILE" 2>&1 || true
  fi

  success "Dependencias del sistema instaladas."
}

# ── Paso 2: Instalar Go ───────────────────────────────────────────────────────
install_go() {
  step "Paso 2/6: Verificando / Instalando Go"

  if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    success "Go ya instalado: version $CURRENT_GO"
  else
    info "Go no encontrado. Instalando Go $GO_VERSION..."

    ARCH=$(uname -m)
    case "$ARCH" in
      x86_64)  GO_ARCH="amd64" ;;
      aarch64) GO_ARCH="arm64" ;;
      *)        error "Arquitectura no soportada: $ARCH" ;;
    esac

    GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"

    info "Descargando $GO_URL..."
    curl -fsSL "$GO_URL" -o "/tmp/$GO_TAR"

    info "Instalando en /usr/local/go..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/$GO_TAR"
    rm -f "/tmp/$GO_TAR"

    # Agregar Go al PATH del sistema
    if ! grep -q '/usr/local/go/bin' /etc/profile.d/*.sh 2>/dev/null; then
      echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/golang.sh > /dev/null
    fi

    export PATH=$PATH:/usr/local/go/bin
    success "Go $GO_VERSION instalado correctamente."
  fi

  # Configurar GOPATH
  GOPATH="${GOPATH:-$HOME/go}"
  export PATH=$PATH:$GOPATH/bin

  # Hacer el PATH permanente para el usuario actual
  SHELL_RC="$HOME/.bashrc"
  [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"

  if ! grep -q 'GOPATH/bin' "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# Go - Asset Sentinel" >> "$SHELL_RC"
    echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> "$SHELL_RC"
    info "PATH de Go agregado a $SHELL_RC"
  fi
}

# ── Paso 3: Instalar binarios de ProjectDiscovery ────────────────────────────
install_pd_tools() {
  step "Paso 3/6: Instalando herramientas de ProjectDiscovery"

  declare -A TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  )

  for TOOL in "${!TOOLS[@]}"; do
    if command -v "$TOOL" &>/dev/null; then
      success "$TOOL ya esta instalado: $(${TOOL} -version 2>&1 | head -1)"
    else
      info "Instalando $TOOL..."
      if go install -v "${TOOLS[$TOOL]}" >> "$LOG_FILE" 2>&1; then
        success "$TOOL instalado correctamente."
      else
        warn "Fallo la instalacion de $TOOL. Revisa $LOG_FILE para detalles."
      fi
    fi
  done

  # Actualizar templates de Nuclei
  if command -v nuclei &>/dev/null; then
    info "Actualizando templates de Nuclei..."
    nuclei -update-templates -silent >> "$LOG_FILE" 2>&1 && \
      success "Templates de Nuclei actualizados." || \
      warn "No se pudieron actualizar templates (puede no ser critico)."
  fi
}

# ── Paso 4: Configurar el proyecto ───────────────────────────────────────────
setup_project() {
  step "Paso 4/6: Configurando el proyecto en $INSTALL_DIR"

  # Crear directorio si no existe (asumimos que el proyecto ya esta descargado)
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" ]]; then
    info "Copiando proyecto a $INSTALL_DIR..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo cp -r "$SCRIPT_DIR"/. "$INSTALL_DIR/"
    success "Proyecto copiado a $INSTALL_DIR."
  else
    info "Proyecto ya esta en $INSTALL_DIR."
  fi

  # Crear entorno virtual Python
  info "Creando entorno virtual Python en $VENV_DIR..."
  python3 -m venv "$VENV_DIR"

  # Instalar dependencias Python
  info "Instalando dependencias Python (puede tardar unos segundos)..."
  "$VENV_DIR/bin/pip" install --upgrade pip --quiet
  "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet >> "$LOG_FILE" 2>&1
  success "Dependencias Python instaladas."

  # Crear .env si no existe
  if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    warn "Archivo .env creado desde la plantilla. DEBES editarlo con tus credenciales:"
    warn "  nano $INSTALL_DIR/.env"
  else
    info ".env ya existe, no se sobreescribe."
  fi
}

# ── Paso 5: Crear usuario de servicio y permisos ─────────────────────────────
setup_service_user() {
  step "Paso 5/6: Configurando usuario de servicio '$SERVICE_USER'"

  if id "$SERVICE_USER" &>/dev/null; then
    info "Usuario '$SERVICE_USER' ya existe."
  else
    sudo useradd -r -s /sbin/nologin -d "$INSTALL_DIR" "$SERVICE_USER"
    success "Usuario '$SERVICE_USER' creado."
  fi

  sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
  sudo chmod 750 "$INSTALL_DIR"
  sudo chmod 640 "$INSTALL_DIR/.env"
  success "Permisos configurados para $INSTALL_DIR."
}

# ── Paso 6: Instalar servicio systemd ────────────────────────────────────────
install_systemd_service() {
  step "Paso 6/6: Instalando servicio systemd"

  # Necesitamos que el usuario sentinel pueda usar los binarios de Go
  GOPATH_BIN="$(go env GOPATH)/bin"

  sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Asset Sentinel - Monitoreo Continuo de Activos
Documentation=file://${INSTALL_DIR}/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/python main.py
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${GOPATH_BIN}"
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
# Hardening de seguridad
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable asset-sentinel

  success "Servicio systemd instalado y habilitado."
  info "El servicio NO se inicia automaticamente hasta que configures el .env."
}

# ── Resumen final ─────────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}${BOLD}║         INSTALACION COMPLETADA EXITOSAMENTE          ║${RESET}"
  echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
  echo ""
  echo -e "${BOLD}Directorio del proyecto:${RESET}  $INSTALL_DIR"
  echo -e "${BOLD}Log de instalacion:${RESET}       $LOG_FILE"
  echo ""
  echo -e "${YELLOW}${BOLD}PASOS FINALES (manuales):${RESET}"
  echo ""
  echo -e "  ${CYAN}1.${RESET} Edita el archivo de configuracion:"
  echo -e "     ${BOLD}sudo nano $INSTALL_DIR/.env${RESET}"
  echo ""
  echo -e "  ${CYAN}2.${RESET} Agrega tus dominios objetivo:"
  echo -e "     ${BOLD}sudo nano $INSTALL_DIR/config/targets.txt${RESET}"
  echo ""
  echo -e "  ${CYAN}3.${RESET} Inicia el servicio:"
  echo -e "     ${BOLD}sudo systemctl start asset-sentinel${RESET}"
  echo ""
  echo -e "  ${CYAN}4.${RESET} Verifica que este corriendo:"
  echo -e "     ${BOLD}sudo systemctl status asset-sentinel${RESET}"
  echo ""
  echo -e "  ${CYAN}5.${RESET} Ver logs en tiempo real:"
  echo -e "     ${BOLD}sudo journalctl -u asset-sentinel -f${RESET}"
  echo ""
  echo -e "${RED}${BOLD}IMPORTANTE:${RESET} Solo escanea dominios con autorizacion expresa."
  echo ""
}

# ── Verificar binarios al final ───────────────────────────────────────────────
verify_installation() {
  echo ""
  info "Verificando instalacion de herramientas..."
  local ALL_OK=true

  for BIN in subfinder httpx nuclei python3; do
    if command -v "$BIN" &>/dev/null; then
      success "$BIN: $(command -v $BIN)"
    else
      warn "$BIN: NO ENCONTRADO en PATH"
      ALL_OK=false
    fi
  done

  if [[ "$ALL_OK" = false ]]; then
    warn "Algunos binarios no estan en el PATH actual."
    warn "Ejecuta 'source ~/.bashrc' o abre una nueva terminal e intenta de nuevo."
  fi
}

# ── Punto de entrada ──────────────────────────────────────────────────────────
main() {
  banner
  check_root
  check_fedora
  check_internet

  install_system_deps
  install_go
  install_pd_tools
  setup_project
  setup_service_user
  install_systemd_service
  verify_installation
  print_summary
}

main "$@"
