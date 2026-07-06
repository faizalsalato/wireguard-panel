#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  WireGuard Panel – Instalador Automático
#  Baixa os ficheiros directamente do GitHub
#
#  Uso:
#    sudo bash install.sh
#    sudo bash install.sh --uninstall
#    sudo PORT=8080 bash install.sh
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Repositório GitHub ─────────────────────────────────────────
# Altere estas variáveis para o seu repositório
GITHUB_USER="faizalsalato"
GITHUB_REPO="wireguard-panel"
GITHUB_BRANCH="main"

# URL base do raw do GitHub
RAW_BASE="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"

# Ficheiros a descarregar  →  formato: "caminho_remoto|caminho_local_destino"
# O caminho local é relativo a INSTALL_DIR
DOWNLOAD_FILES=(
  "server.js|server.js"
  "public/index.html|public/index.html"
)

# ── Configurações ──────────────────────────────────────────────
INSTALL_DIR="/opt/wg-panel"
SERVICE_NAME="wg-panel"
PORT="${PORT:-4000}"
WG_DIR="/etc/wireguard"
NODE_MIN_VERSION=16

# ── Cores ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[AVISO]${RESET} $*"; }
log_error()   { echo -e "${RED}[ERRO]${RESET}  $*"; }
log_section() { echo -e "\n${BOLD}${CYAN}▶ $*${RESET}"; }

die() {
  log_error "$*"
  exit 1
}

confirm() {
  local msg="$1"
  local default="${2:-s}"
  local prompt
  [[ "$default" == "s" ]] && prompt="[S/n]" || prompt="[s/N]"
  read -rp "$(echo -e "${YELLOW}?${RESET} ${msg} ${prompt}: ")" answer
  answer="${answer:-$default}"
  [[ "${answer,,}" == "s" ]]
}

banner() {
  echo -e "${CYAN}"
  cat <<'EOF'
  ╔══════════════════════════════════════════╗
  ║        WireGuard Panel Installer         ║
  ║      Instalador Automático v1.0          ║
  ╚══════════════════════════════════════════╝
EOF
  echo -e "${RESET}"
  echo -e "  Repositório: ${BOLD}https://github.com/${GITHUB_USER}/${GITHUB_REPO}${RESET}"
  echo -e "  Branch:      ${BOLD}${GITHUB_BRANCH}${RESET}\n"
}

# ── Verificações iniciais ──────────────────────────────────────
check_root() {
  if [[ $EUID -ne 0 ]]; then
    die "Este script precisa de ser executado como root.\n  Tente: sudo bash install.sh"
  fi
}

check_os() {
  [[ -f /etc/os-release ]] || die "Sistema operativo não suportado."
  source /etc/os-release
  log_info "Sistema detectado: ${PRETTY_NAME}"

  case "$ID" in
    ubuntu|debian|raspbian) PKG_MANAGER="apt"    ;;
    centos|rhel|fedora)     PKG_MANAGER="yum"    ;;
    arch|manjaro)           PKG_MANAGER="pacman" ;;
    *)
      log_warn "Distribuição '$ID' não testada. Continuando com apt..."
      PKG_MANAGER="apt"
      ;;
  esac
}

check_internet() {
  log_section "Verificando conectividade"
  if curl -sf --max-time 5 "https://github.com" &>/dev/null; then
    log_ok "Acesso à internet confirmado."
  else
    die "Sem acesso à internet. Verifique a sua ligação."
  fi

  # Verifica se o repositório existe
  HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}" \
    "https://github.com/${GITHUB_USER}/${GITHUB_REPO}" --max-time 10)
  if [[ "$HTTP_STATUS" != "200" ]]; then
    die "Repositório não encontrado: https://github.com/${GITHUB_USER}/${GITHUB_REPO}\n  Verifique as variáveis GITHUB_USER e GITHUB_REPO no topo do script."
  fi
  log_ok "Repositório GitHub acessível."
}

# ── Dependências do sistema ────────────────────────────────────
install_system_deps() {
  log_section "Verificando dependências do sistema"

  # curl (obrigatório para download)
  if ! command -v curl &>/dev/null; then
    log_info "Instalando curl..."
    case "$PKG_MANAGER" in
      apt)    apt-get install -y -q curl ;;
      yum)    yum install -y curl ;;
      pacman) pacman -S --noconfirm curl ;;
    esac
  fi

  # Node.js
  if command -v node &>/dev/null; then
    NODE_VER=$(node -e "process.stdout.write(process.versions.node.split('.')[0])")
    if [[ "$NODE_VER" -ge "$NODE_MIN_VERSION" ]]; then
      log_ok "Node.js $(node --version) já instalado."
    else
      log_warn "Node.js v$NODE_VER encontrado, necessário v$NODE_MIN_VERSION+. Atualizando..."
      install_node
    fi
  else
    log_info "Node.js não encontrado. Instalando..."
    install_node
  fi

  # WireGuard
  if command -v wg &>/dev/null && command -v wg-quick &>/dev/null; then
    log_ok "WireGuard já instalado."
  else
    log_info "WireGuard não encontrado. Instalando..."
    install_wireguard
  fi
}

install_node() {
  log_info "Instalando Node.js LTS via NodeSource..."
  case "$PKG_MANAGER" in
    apt)
      curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - &>/dev/null
      apt-get install -y -q nodejs
      ;;
    yum)
      curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - &>/dev/null
      yum install -y nodejs
      ;;
    pacman)
      pacman -S --noconfirm nodejs npm
      ;;
    *)
      die "Instale Node.js manualmente: https://nodejs.org"
      ;;
  esac
  log_ok "Node.js $(node --version) instalado."
}

install_wireguard() {
  case "$PKG_MANAGER" in
    apt)
      apt-get update -q
      apt-get install -y -q wireguard wireguard-tools
      ;;
    yum)
      yum install -y epel-release
      yum install -y wireguard-tools
      ;;
    pacman)
      pacman -S --noconfirm wireguard-tools
      ;;
    *)
      die "Instale WireGuard manualmente: https://www.wireguard.com/install/"
      ;;
  esac
  log_ok "WireGuard instalado."
}

# ── Download dos ficheiros do GitHub ──────────────────────────
download_files() {
  log_section "Baixando ficheiros do GitHub"

  mkdir -p "$INSTALL_DIR/public"
  mkdir -p "$WG_DIR"

  local failed=0

  for entry in "${DOWNLOAD_FILES[@]}"; do
    local remote="${entry%%|*}"   # parte antes do |
    local local_path="${entry##*|}" # parte depois do |
    local dest="$INSTALL_DIR/$local_path"
    local url="$RAW_BASE/$remote"

    # Garante que a pasta destino existe
    mkdir -p "$(dirname "$dest")"

    log_info "Baixando: $remote"
    if curl -fsSL --max-time 30 "$url" -o "$dest"; then
      log_ok "  → $dest"
    else
      log_error "  Falha ao baixar: $url"
      failed=1
    fi
  done

  if [[ $failed -eq 1 ]]; then
    die "Um ou mais ficheiros falharam ao ser baixados.\nVerifique se os ficheiros existem no branch '${GITHUB_BRANCH}' do repositório."
  fi

  # Gera package.json mínimo
  if [[ ! -f "$INSTALL_DIR/package.json" ]]; then
    cat > "$INSTALL_DIR/package.json" <<EOF
{
  "name": "wg-panel",
  "version": "1.0.0",
  "description": "WireGuard Web Panel",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  }
}
EOF
    log_ok "package.json criado."
  fi

  # Permissões
  chmod 750 "$INSTALL_DIR"
  chmod 640 "$INSTALL_DIR/server.js"
  chmod 640 "$INSTALL_DIR/public/index.html"
  chmod 700 "$WG_DIR"

  log_ok "Todos os ficheiros baixados com sucesso."
}

# ── Instalar dependências npm ──────────────────────────────────
install_npm_deps() {
  log_section "Instalando dependências Node.js"
  cd "$INSTALL_DIR"
  npm install --omit=dev --silent express multer
  log_ok "Dependências npm instaladas (express, multer)."
}

# ── Serviço systemd ────────────────────────────────────────────
setup_systemd() {
  log_section "Configurando serviço systemd"

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=WireGuard Web Panel
Documentation=https://github.com/${GITHUB_USER}/${GITHUB_REPO}
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(which node) ${INSTALL_DIR}/server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

Environment=NODE_ENV=production
Environment=PORT=${PORT}
Environment=WG_DIR=${WG_DIR}

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" &>/dev/null
  log_ok "Serviço systemd criado e activado no boot."
}

# ── Firewall (iptables) ─────────────────────────────────────────
setup_firewall() {
  log_section "Configuração de firewall (iptables)"

  if ! command -v iptables &>/dev/null; then
    log_warn "iptables não está instalado."
    return
  fi

  if confirm "Abrir porta $PORT no iptables?"; then

    # Verifica se a regra já existe
    if iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
      log_info "A porta $PORT já está liberada."
    else
      iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
      log_ok "Porta $PORT liberada no iptables."
    fi

    # Salva as regras (Debian/Ubuntu)
    if command -v netfilter-persistent &>/dev/null; then
      netfilter-persistent save &>/dev/null
      log_info "Regras salvas com netfilter-persistent."
    elif command -v iptables-save &>/dev/null; then
      mkdir -p /etc/iptables
      iptables-save > /etc/iptables/rules.v4
      log_info "Regras salvas em /etc/iptables/rules.v4."
    else
      log_warn "Não foi possível salvar as regras automaticamente."
      log_warn "Após reiniciar, as regras poderão ser perdidas."
    fi

  else
    log_warn "Porta não aberta."
  fi
}


# ── Arranque e verificação ─────────────────────────────────────
start_and_verify() {
  log_section "Iniciando serviço"

  systemctl start "$SERVICE_NAME"
  sleep 2

  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Serviço $SERVICE_NAME está a correr."
  else
    log_error "Serviço falhou ao iniciar. Últimos logs:"
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager
    die "Instalação falhou no arranque do serviço."
  fi

  sleep 1
  if curl -sf --max-time 5 "http://localhost:$PORT/configs" &>/dev/null; then
    log_ok "Healthcheck HTTP passou (porta $PORT responde)."
  else
    log_warn "Healthcheck falhou – o servidor pode ainda estar a arrancar. Tente em alguns segundos."
  fi
}

# ── Atualizar ──────────────────────────────────────────────────
update() {
  log_section "Atualizando WireGuard Panel"
  log_info "Parando serviço..."
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true

  check_internet
  download_files

  log_info "Reiniciando serviço..."
  systemctl start "$SERVICE_NAME"
  sleep 2

  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Atualização concluída. Serviço a correr."
  else
    die "Falha após atualização. Ver: sudo journalctl -u $SERVICE_NAME -n 30"
  fi
  exit 0
}

# ── Desinstalar ────────────────────────────────────────────────
uninstall() {
  log_section "Desinstalar WireGuard Panel"
  confirm "Tem a certeza que quer desinstalar?" "n" || { log_info "Cancelado."; exit 0; }

  systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload

  if confirm "Apagar ficheiros de $INSTALL_DIR?"; then
    rm -rf "$INSTALL_DIR"
    log_ok "Ficheiros removidos."
  fi

  log_ok "WireGuard Panel desinstalado com sucesso."
  exit 0
}

# ── Sumário final ──────────────────────────────────────────────
print_summary() {
  LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

  echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}${BOLD}   Instalação concluída com sucesso!  ✓${RESET}"
  echo -e "${GREEN}${BOLD}════════════════════════════════════════════════${RESET}"
  echo ""
  echo -e "  ${BOLD}Painel:${RESET}        http://localhost:${PORT}"
  echo -e "  ${BOLD}Rede local:${RESET}    http://${LOCAL_IP}:${PORT}"
  echo -e "  ${BOLD}Instalação:${RESET}    ${INSTALL_DIR}"
  echo -e "  ${BOLD}Configs WG:${RESET}    ${WG_DIR}"
  echo -e "  ${BOLD}Repositório:${RESET}   https://github.com/${GITHUB_USER}/${GITHUB_REPO}"
  echo ""
  echo -e "  ${BOLD}Comandos úteis:${RESET}"
  echo -e "  ${CYAN}sudo systemctl status  ${SERVICE_NAME}${RESET}   → estado"
  echo -e "  ${CYAN}sudo systemctl restart ${SERVICE_NAME}${RESET}   → reiniciar"
  echo -e "  ${CYAN}sudo journalctl -u ${SERVICE_NAME} -f${RESET}    → logs em tempo real"
  echo -e "  ${CYAN}sudo bash install.sh --update${RESET}            → atualizar do GitHub"
  echo -e "  ${CYAN}sudo bash install.sh --uninstall${RESET}         → desinstalar"
  echo ""
}

# ── Entry point ────────────────────────────────────────────────
main() {
  banner

  case "${1:-}" in
    --uninstall|-u) check_root; check_os; uninstall ;;
    --update|-U)    check_root; check_os; update ;;
  esac

  check_root
  check_os

  echo -e "  ${BOLD}Porto:${RESET}         ${PORT}"
  echo -e "  ${BOLD}Instalação:${RESET}    ${INSTALL_DIR}"
  echo -e "  ${BOLD}WireGuard:${RESET}     ${WG_DIR}"
  echo ""

  confirm "Iniciar instalação?" || { log_info "Cancelado."; exit 0; }

  check_internet
  install_system_deps
  download_files
  install_npm_deps
  setup_systemd
  setup_firewall
  start_and_verify
  print_summary
}

main "$@"
