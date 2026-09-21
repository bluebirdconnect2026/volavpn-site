#!/usr/bin/env bash
# vola-server.sh — turn a fresh Ubuntu 22.04/24.04 server (x86_64 or arm64) into an
# IKEv2 VPN server that iPhone / iPad / Mac can use with a username + password.
#
#   sudo bash vola-server.sh install [--host <fqdn>] [--email <addr>] [--user <name>] [--name <label>]
#   sudo vola-server user add <name> [--out <file>] [--reset] [--no-qr] [--name <label>]
#   sudo vola-server user del <name>
#   sudo vola-server user list
#   sudo vola-server qr <name> [--with-password] [--name <label>]
#   sudo vola-server profile <name> [--with-password] [--name <label>] --out <file.mobileconfig>
#   sudo vola-server status
#   sudo vola-server client <name> [--json] [--name <label>]
#   sudo vola-server uninstall [--yes]
#
# Design (details in README.md):
#   strongSwan (charon-systemd + swanctl), server authenticates with a publicly trusted
#   certificate whose name == IKE identity == client "Remote ID"; users authenticate with
#   EAP-MSCHAPv2 (username/password). Passwords are stored as NT hashes, which are
#   equivalent to the password for VPN login (root-only files; keep them out of backups).
#   Certificates: Let's Encrypt first, ZeroSSL as fallback (or any ACME CA with EAB).
#   Logs: strongSwan logs to its own volatile journal namespace (RAM only, hourly files,
#   files older than 24 h deleted).
#   Sharing: `qr`, `profile` and `client` hand a line to the Vola app as a vola-line/1 link
#   (QR code or text) or as a .mobileconfig. The password is included only with
#   --with-password: the server keeps only a hash, so the password is typed in and checked
#   against that hash first. Secrets never go on a command line (python3 / qrencode read them
#   from stdin) and are never written to a log.
#
# Safe to re-run: every step rewrites its own files and rebuilds its own firewall chains.

set -euo pipefail
umask 077

readonly KIT_VERSION="1.1.0"
readonly SELF_INSTALL=/usr/local/sbin/vola-server
readonly STATE_DIR=/etc/vola-server
readonly STATE_FILE=$STATE_DIR/server.env
readonly USERS_DIR=$STATE_DIR/users
readonly SWAN_DIR=/etc/swanctl
readonly SWAN_CONN=$SWAN_DIR/conf.d/vola.conf
readonly SWAN_SECRETS=$SWAN_DIR/conf.d/vola-secrets.conf
readonly SWAN_LOGCONF=/etc/strongswan.d/vola-logging.conf
readonly JOURNAL_NS=vola
readonly JOURNAL_NS_CONF=/etc/systemd/journald@${JOURNAL_NS}.conf
readonly SYSCTL_FILE=/etc/sysctl.d/60-vola-vpn.conf
readonly SSH_DROPIN=/etc/ssh/sshd_config.d/00-vola-keys-only.conf
readonly FW_UNIT=/etc/systemd/system/vola-firewall.service
readonly CERT_NAME=vola
readonly LE_LIVE=/etc/letsencrypt/live/$CERT_NAME
readonly DEPLOY_HOOK=/etc/letsencrypt/renewal-hooks/deploy/vola-swanctl
readonly ZEROSSL_ACME=https://acme.zerossl.com/v2/DV90
readonly ZEROSSL_EAB_API=https://api.zerossl.com/acme/eab-credentials-email

# Defaults (can be overridden on install; persisted in $STATE_FILE).
readonly DEFAULT_POOL4=10.99.0.0/22                 # 1022 client addresses
readonly DEFAULT_POOL6=fd76:6f6c:6100::/118         # ULA, never forwarded (see README)
readonly DEFAULT_DNS="1.1.1.1,9.9.9.9"              # Cloudflare + Quad9
readonly DEFAULT_LABEL="My server"                  # line name shown in the Vola app
readonly LINE_MAX_BYTES=1024                        # vola-line/1 size limit (DESIGN-2 §4.15.1)

# Proposals: AEAD first, then AES-CBC + SHA-2. No 3DES, no SHA-1, no MD5, no MODP-1024/1536.
# Covers NEVPNProtocolIKEv2 defaults (AES-256 / SHA2-256 / DH14, no PFS) used by the Vola app
# and the defaults of a manually created IKEv2 profile on iOS / macOS.
readonly IKE_PROPOSALS="aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256,aes256gcm16-prfsha256-modp2048,aes128gcm16-prfsha256-ecp256,aes256-sha384-ecp384,aes256-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-ecp256,aes128-sha256-modp2048"
# ESP: without a DH group (iOS default: no PFS) and with one (clients that enable PFS).
readonly ESP_PROPOSALS="aes256gcm16,aes128gcm16,aes256-sha256,aes256-sha384,aes128-sha256,aes256gcm16-ecp384,aes256gcm16-ecp256,aes256gcm16-modp2048,aes256-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-modp2048"

# Packages the kit needs (the ones not already present are recorded and purged on uninstall).
readonly BASE_PKGS=(charon-systemd strongswan-swanctl libcharon-extauth-plugins
                    libcharon-extra-plugins libstrongswan-standard-plugins
                    libstrongswan-extra-plugins certbot iptables openssl curl ca-certificates
                    python3 unattended-upgrades iproute2 qrencode)

# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------
if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'; else B=; R=; G=; Y=; N=; fi
say()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s ok%s  %s\n' "$G" "$N" "$*"; }
warn() { printf '%swarn%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "run as root (sudo)."; }

have() { command -v "$1" >/dev/null 2>&1; }

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

valid_fqdn() {
  [[ ${#1} -le 253 && $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}
valid_ipv4() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o; for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
valid_user() { [[ $1 =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ ]]; }

# Line name (--name): surrounding blanks trimmed, inner runs of blanks collapsed (as the app
# does); then 1-32 characters and no control characters.
norm_label() { local w; read -r -a w <<<"$1"; printf '%s' "${w[*]}"; }
valid_label() {
  [[ -n $1 && ! $1 =~ [[:cntrl:]] ]] || return 1
  if have python3; then
    python3 -c 'import sys; sys.exit(0 if 1 <= len(sys.argv[1]) <= 32 else 1)' "$1"
  else
    (( ${#1} <= 128 ))   # bytes; python3 is normally present (cloud-init needs it)
  fi
}

# key=value state file (values never contain secrets)
state_get() { [[ -f $STATE_FILE ]] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -n1 | tr -d "'" || true; }
state_set() {
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  touch "$STATE_FILE"; chmod 600 "$STATE_FILE"
  local tmp; tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
  grep -v "^$1=" "$STATE_FILE" >"$tmp" || true
  printf "%s='%s'\n" "$1" "$2" >>"$tmp"
  mv "$tmp" "$STATE_FILE"; chmod 600 "$STATE_FILE"
}

require_installed() {
  [[ -f $STATE_FILE && -n $(state_get HOST) ]] || die "not installed yet — run: sudo bash $0 install"
}

swan_unit() {
  # The unit that runs charon-systemd is strongswan.service on current Ubuntu,
  # strongswan-swanctl.service on some older builds (often an alias).
  local u id
  for u in strongswan.service strongswan-swanctl.service; do
    if systemctl cat "$u" 2>/dev/null | grep -q 'charon-systemd'; then
      id=$(systemctl show -p Id --value "$u" 2>/dev/null || true)
      echo "${id:-$u}"; return 0
    fi
  done
  echo strongswan.service
}

detect_public_ip() {
  local url ip
  for url in https://checkip.amazonaws.com https://api.ipify.org https://ipv4.icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 8 "$url" 2>/dev/null | tr -d '[:space:]') || true
    if valid_ipv4 "${ip:-}"; then echo "$ip"; return 0; fi
  done
  return 1
}

resolves_to() { # host ip -> 0 if an A record of host equals ip
  getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u | grep -qx "$2"
}

# ---------------------------------------------------------------------------------------------
# install steps
# ---------------------------------------------------------------------------------------------
check_os() {
  [[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04) ok "OS: ${PRETTY_NAME:-$ID $VERSION_ID} ($(uname -m))" ;;
    ubuntu:*|debian:*) warn "untested OS ${PRETTY_NAME:-$ID}; continuing (supported: Ubuntu 22.04 / 24.04)" ;;
    *) die "unsupported OS ${PRETTY_NAME:-unknown}; this kit supports Ubuntu 22.04 / 24.04" ;;
  esac
  case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) warn "untested CPU architecture $(uname -m)";; esac
}

install_packages() {
  say "Installing packages"
  export DEBIAN_FRONTEND=noninteractive
  local pkgs=("${BASE_PKGS[@]}") added p prev
  # Firewall persistence: netfilter-persistent, unless ufw is active (the two conflict in apt).
  if ! ufw_active; then pkgs+=(iptables-persistent); fi
  prev=$(state_get PKGS_ADDED)
  added=$prev
  for p in "${pkgs[@]}"; do
    if ! pkg_installed "$p"; then added="$added $p"; fi
  done
  # Don't let iptables-persistent snapshot rules during install; we save explicitly later.
  echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | debconf-set-selections
  echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections
  ( umask 022
    apt-get update -qq
    apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      --no-install-recommends "${pkgs[@]}" >/dev/null )
  # de-duplicate the list of packages we added
  added=$(tr ' ' '\n' <<<"$added" | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//')
  state_set PKGS_ADDED "$added"
  # The legacy ipsec/stroke starter would fight charon-systemd for UDP 500/4500.
  if systemctl list-unit-files strongswan-starter.service >/dev/null 2>&1 \
     && systemctl is-enabled --quiet strongswan-starter.service 2>/dev/null; then
    systemctl disable --now strongswan-starter.service >/dev/null 2>&1 || true
    warn "disabled strongswan-starter.service (conflicts with charon-systemd)"
  fi
  ok "packages installed"
}

configure_sysctl() {
  say "Enabling IPv4 forwarding"
  if [[ -z $(state_get IPFWD_BEFORE) ]]; then
    state_set IPFWD_BEFORE "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
  fi
  umask 022
  cat >"$SYSCTL_FILE" <<'EOF'
# managed by vola-server — removed by `vola-server uninstall`
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
  umask 077
  sysctl -q -p "$SYSCTL_FILE"
  ok "net.ipv4.ip_forward = $(sysctl -n net.ipv4.ip_forward)"
}

ufw_active() { have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; }

# Remove every jump from a built-in chain to one of our chains, then insert it at position 1,
# i.e. before any distribution REJECT (Oracle images end INPUT/FORWARD with REJECT).
fw_jump_first() { # cmd table chain target
  local cmd=$1 table=$2 chain=$3 target=$4
  while "$cmd" -w -t "$table" -C "$chain" -j "$target" 2>/dev/null; do
    "$cmd" -w -t "$table" -D "$chain" -j "$target"
  done
  "$cmd" -w -t "$table" -I "$chain" 1 -j "$target"
}
fw_chain_reset() { # cmd table chain
  "$1" -w -t "$2" -N "$3" 2>/dev/null || true
  "$1" -w -t "$2" -F "$3"
}
fw_chain_drop() { # cmd table builtin chain
  local cmd=$1 table=$2 builtin=$3 chain=$4
  while "$cmd" -w -t "$table" -C "$builtin" -j "$chain" 2>/dev/null; do
    "$cmd" -w -t "$table" -D "$builtin" -j "$chain"
  done
  "$cmd" -w -t "$table" -F "$chain" 2>/dev/null || true
  "$cmd" -w -t "$table" -X "$chain" 2>/dev/null || true
}

firewall_apply() {
  local pool4 pool6 net
  pool4=$(state_get POOL4); pool4=${pool4:-$DEFAULT_POOL4}
  pool6=$(state_get POOL6); pool6=${pool6:-$DEFAULT_POOL6}

  # --- IPv4 filter ---
  fw_chain_reset iptables filter VOLA-IN
  # Decrypted VPN client traffic addressed to the server itself (e.g. sshd) goes through INPUT.
  # Clients need no service on the server (DNS goes to public resolvers), so refuse all of it —
  # otherwise VPN users would bypass the cloud firewall's source restriction on SSH.
  iptables -w -A VOLA-IN -s "$pool4" -j REJECT --reject-with icmp-admin-prohibited
  iptables -w -A VOLA-IN -p udp -m multiport --dports 500,4500 -j ACCEPT
  iptables -w -A VOLA-IN -p esp -j ACCEPT
  # TCP 80 is only used by the ACME HTTP-01 challenge (certbot listens only while issuing/renewing).
  iptables -w -A VOLA-IN -p tcp --dport 80 -j ACCEPT
  fw_jump_first iptables filter INPUT VOLA-IN

  fw_chain_reset iptables filter VOLA-FWD
  # VPN clients must not reach cloud metadata / the provider's private network through us.
  # (This also isolates VPN clients from each other.)
  for net in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do
    iptables -w -A VOLA-FWD -s "$pool4" -d "$net" -j REJECT --reject-with icmp-net-prohibited
  done
  if iptables -w -A VOLA-FWD -s "$pool4" -m policy --dir in --pol ipsec --proto esp -j ACCEPT 2>/dev/null; then
    iptables -w -A VOLA-FWD -d "$pool4" -m policy --dir out --pol ipsec --proto esp -j ACCEPT
  else
    iptables -w -A VOLA-FWD -s "$pool4" -j ACCEPT
    iptables -w -A VOLA-FWD -d "$pool4" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  fi
  fw_jump_first iptables filter FORWARD VOLA-FWD

  # --- IPv4 NAT + MSS clamp (IPsec overhead) ---
  fw_chain_reset iptables nat VOLA-POST
  if ! iptables -w -t nat -A VOLA-POST -s "$pool4" ! -d "$pool4" -m policy --dir out --pol none -j MASQUERADE 2>/dev/null; then
    iptables -w -t nat -A VOLA-POST -s "$pool4" ! -d "$pool4" -j MASQUERADE
  fi
  fw_jump_first iptables nat POSTROUTING VOLA-POST

  fw_chain_reset iptables mangle VOLA-MSS
  iptables -w -t mangle -A VOLA-MSS -s "$pool4" -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
  iptables -w -t mangle -A VOLA-MSS -d "$pool4" -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
  fw_jump_first iptables mangle FORWARD VOLA-MSS

  # --- IPv6: accept IKE on v6 too; clients' IPv6 is captured by the tunnel and dropped ---
  if have ip6tables; then
    fw_chain_reset ip6tables filter VOLA-IN
    ip6tables -w -A VOLA-IN -s "$pool6" -j REJECT --reject-with icmp6-adm-prohibited
    ip6tables -w -A VOLA-IN -p udp -m multiport --dports 500,4500 -j ACCEPT
    ip6tables -w -A VOLA-IN -p esp -j ACCEPT
    ip6tables -w -A VOLA-IN -p tcp --dport 80 -j ACCEPT
    fw_jump_first ip6tables filter INPUT VOLA-IN
    fw_chain_reset ip6tables filter VOLA-FWD
    ip6tables -w -A VOLA-FWD -s "$pool6" -j REJECT --reject-with icmp6-adm-prohibited
    ip6tables -w -A VOLA-FWD -d "$pool6" -j DROP
    fw_jump_first ip6tables filter FORWARD VOLA-FWD
  fi
}

firewall_remove() {
  fw_chain_drop iptables filter INPUT VOLA-IN
  fw_chain_drop iptables filter FORWARD VOLA-FWD
  fw_chain_drop iptables nat POSTROUTING VOLA-POST
  fw_chain_drop iptables mangle FORWARD VOLA-MSS
  if have ip6tables; then
    fw_chain_drop ip6tables filter INPUT VOLA-IN
    fw_chain_drop ip6tables filter FORWARD VOLA-FWD
  fi
}

fw_pos() { iptables -w -L "$1" -n --line-numbers | awk -v t="$2" '$2==t {print $1; exit}'; }

firewall_persist() {
  if have netfilter-persistent && ! ufw_active; then
    if netfilter-persistent save >/dev/null 2>&1; then
      ok "firewall saved (netfilter-persistent)"
    else
      warn "netfilter-persistent save failed; vola-firewall.service will still re-apply at boot"
    fi
  fi
}

configure_firewall() {
  say "Configuring firewall"
  if ufw_active; then
    ufw allow 500,4500/udp >/dev/null
    ufw allow 80/tcp >/dev/null
    ok "ufw: allowed UDP 500,4500 and TCP 80"
  fi
  firewall_apply
  # A tiny unit re-applies our chains at boot, after netfilter-persistent / ufw restored theirs.
  umask 022
  cat >"$FW_UNIT" <<EOF
[Unit]
Description=Vola VPN firewall rules (IKE ports, forwarding, NAT)
After=network-pre.target netfilter-persistent.service ufw.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$SELF_INSTALL firewall-apply

[Install]
WantedBy=multi-user.target
EOF
  umask 077
  systemctl daemon-reload
  systemctl enable vola-firewall.service >/dev/null 2>&1
  # start it now too (it only re-applies the same chains), so `status` shows it active
  systemctl start vola-firewall.service >/dev/null 2>&1 || warn "vola-firewall.service did not start"
  firewall_persist
  ok "VOLA-IN is rule #$(fw_pos INPUT VOLA-IN) of INPUT, VOLA-FWD is rule #$(fw_pos FORWARD VOLA-FWD) of FORWARD (ahead of any distro REJECT)"
}

port80_busy() { ss -Hltn 'sport = :80' 2>/dev/null | grep -q .; }

cert_domain() { # domain of the existing lineage, if any
  [[ -f $LE_LIVE/cert.pem ]] || return 0
  openssl x509 -in "$LE_LIVE/cert.pem" -noout -ext subjectAltName 2>/dev/null \
    | grep -o 'DNS:[^, ]*' | head -1 | cut -d: -f2
}

# The EAB HMAC key is a secret: pass it to certbot in a root-only config file, never on the
# command line (other local users can read /proc/*/cmdline while certbot runs).
certbot_eab_conf() { # hmac -> path of a temp certbot config file holding it
  local f; f=$(mktemp "$STATE_DIR/.certbot-eab.XXXXXX")
  chmod 600 "$f"
  printf 'eab-hmac-key = %s\n' "$1" >"$f"
  echo "$f"
}

certbot_run() { # extra args...
  certbot certonly --standalone --non-interactive --agree-tos --quiet \
    --cert-name "$CERT_NAME" -d "$HOST" --preferred-challenges http \
    --key-type rsa --rsa-key-size 2048 --keep-until-expiring "$@"
}

email_args() {
  if [[ -n $EMAIL ]]; then printf '%s\n' -m "$EMAIL"; else printf '%s\n' --register-unsafely-without-email; fi
}

issue_letsencrypt() {
  local args=(); mapfile -t args < <(email_args)
  say "Requesting certificate from Let's Encrypt for $HOST"
  certbot_run "${args[@]}"
}

issue_zerossl() {
  [[ -n $EMAIL ]] || { warn "ZeroSSL fallback needs --email <addr> (ZeroSSL accounts need an email address)"; return 1; }
  say "Requesting certificate from ZeroSSL for $HOST"
  local json kid hmac
  json=$(curl -fsS --max-time 20 --data-urlencode "email=$EMAIL" "$ZEROSSL_EAB_API") \
    || { warn "could not get ZeroSSL EAB credentials"; return 1; }
  kid=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("eab_kid",""))' <<<"$json")
  hmac=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("eab_hmac_key",""))' <<<"$json")
  [[ -n $kid && -n $hmac ]] || { warn "ZeroSSL did not return EAB credentials"; return 1; }
  local conf rc=0; conf=$(certbot_eab_conf "$hmac"); hmac=""
  certbot_run --config "$conf" --server "$ZEROSSL_ACME" --eab-kid "$kid" -m "$EMAIL" || rc=$?
  rm -f "$conf"
  return $rc
}

issue_custom() {
  [[ -n $ACME_SERVER ]] || return 1
  say "Requesting certificate from $ACME_SERVER for $HOST"
  local args=(--server "$ACME_SERVER") conf="" rc=0
  if [[ -n $EAB_KID ]]; then
    conf=$(certbot_eab_conf "$EAB_HMAC")
    args=(--config "$conf" "${args[@]}" --eab-kid "$EAB_KID")
  fi
  local e=(); mapfile -t e < <(email_args)
  certbot_run "${args[@]}" "${e[@]}" || rc=$?
  [[ -n $conf ]] && rm -f "$conf"
  return $rc
}

obtain_certificate() {
  say "Certificate for $HOST"
  local existing; existing=$(cert_domain)
  if [[ -n $existing && $existing != "$HOST" ]]; then
    warn "existing certificate is for $existing; replacing it"
    certbot delete --cert-name "$CERT_NAME" --non-interactive >/dev/null 2>&1 || true
  fi
  if [[ -n $existing && $existing == "$HOST" ]] && openssl x509 -in "$LE_LIVE/cert.pem" -noout -checkend $((30*86400)) >/dev/null 2>&1; then
    ok "valid certificate already present (renewal is automatic)"
  else
    port80_busy && die "TCP port 80 is in use by another program; certbot needs it briefly to prove domain ownership. Stop that program and re-run."
    local done_=0
    case "$CA" in
      auto)
        if issue_letsencrypt; then done_=1
        else
          warn "Let's Encrypt failed (rate limit on shared domains like sslip.io is common) — trying the fallback CA"
          if issue_zerossl; then done_=1; elif issue_custom; then done_=1; fi
        fi ;;
      letsencrypt) issue_letsencrypt && done_=1 ;;
      zerossl)     issue_zerossl && done_=1 ;;
      custom)      issue_custom && done_=1 ;;
      *) die "unknown --ca '$CA' (auto|letsencrypt|zerossl|custom)" ;;
    esac
    [[ $done_ -eq 1 ]] || die "could not obtain a certificate. Check: DNS of $HOST points here, TCP 80 is open in the cloud firewall, and (for the fallback) pass --email."
    ok "certificate issued"
  fi
  install_deploy_hook
  "$DEPLOY_HOOK"
}

install_deploy_hook() {
  mkdir -p "$(dirname "$DEPLOY_HOOK")"
  umask 022
  cat >"$DEPLOY_HOOK" <<'EOF'
#!/bin/sh
# managed by vola-server: copy the renewed certificate into swanctl, reload credentials + connection.
set -eu
mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
L="${RENEWED_LINEAGE:-/etc/letsencrypt/live/vola}"
[ "$(basename "$L")" = "vola" ] || exit 0
install -m 644 "$L/cert.pem" /etc/swanctl/x509/vola.pem
rm -f /etc/swanctl/x509ca/vola-chain-*.pem
awk '/-----BEGIN CERTIFICATE-----/{n++} n{print > ("/etc/swanctl/x509ca/vola-chain-" n ".pem")}' "$L/chain.pem"
chmod 644 /etc/swanctl/x509ca/vola-chain-*.pem
install -m 600 "$L/privkey.pem" /etc/swanctl/private/vola.key
if [ -S /var/run/charon.vici ] || [ -S /run/charon.vici ]; then
  # --load-creds alone is not enough: the connection keeps the certificate it was loaded
  # with, so reload it too (already-established sessions are not affected).
  swanctl --load-creds --clear --noprompt >/dev/null 2>&1 && swanctl --load-conns >/dev/null 2>&1 \
    || logger -t vola-server "swanctl reload after renewal failed"
fi
EOF
  chmod 755 "$DEPLOY_HOOK"
  umask 077
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
}

nt_hash() { # password on stdin -> hex NT hash (MD4 of UTF-16LE); empty if MD4 unavailable
  iconv -f UTF-8 -t UTF-16LE 2>/dev/null \
    | { openssl dgst -md4 -provider legacy -provider default -r 2>/dev/null || openssl dgst -md4 -r 2>/dev/null; } \
    | awk '{print $1}' | grep -E '^[0-9a-f]{32}$' || true
}

write_secrets() {
  # Rebuild the swanctl secrets file from $USERS_DIR (one file per user, root-only).
  local tmp f name i=0
  tmp=$(mktemp "$SWAN_DIR/conf.d/.vola-secrets.XXXXXX")
  {
    echo "# managed by vola-server — do not edit; use 'vola-server user ...'"
    echo "secrets {"
    shopt -s nullglob
    for f in "$USERS_DIR"/*; do
      name=$(basename "$f"); valid_user "$name" || continue
      i=$((i+1))
      local nthash="" eapsecret=""
      nthash=$(sed -n 's/^NTHASH=//p' "$f")
      eapsecret=$(sed -n 's/^EAP=//p' "$f")
      if [[ -n $nthash ]]; then
        printf '  ntlm-u%d {\n    id = %s\n    secret = 0x%s\n  }\n' "$i" "$name" "$nthash"
      elif [[ -n $eapsecret ]]; then
        printf '  eap-u%d {\n    id = %s\n    secret = %s\n  }\n' "$i" "$name" "$eapsecret"
      fi
    done
    shopt -u nullglob
    echo "}"
  } >"$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$SWAN_SECRETS"
}

write_strongswan_config() {
  say "Writing strongSwan configuration"
  local pool4 pool6 dns unit
  pool4=$(state_get POOL4); pool6=$(state_get POOL6); dns=$(state_get DNS)
  mkdir -p "$SWAN_DIR/conf.d" "$USERS_DIR"; chmod 700 "$USERS_DIR"

  umask 022
  cat >"$SWAN_CONN" <<EOF
# managed by vola-server $KIT_VERSION — re-generated on every 'install'
connections {
  vola {
    version = 2
    proposals = $IKE_PROPOSALS
    local_addrs = %any
    pools = vola-v4, vola-v6
    send_cert = always
    send_certreq = no
    fragmentation = yes
    mobike = yes
    # one account may be used on several devices at once
    unique = never
    dpd_delay = 300s
    # clients (iOS/macOS: 24 h) drive rekeying; server-initiated rekeys can pick a DH group
    # the client did not ask for.
    rekey_time = 0s
    local {
      auth = pubkey
      certs = vola.pem
      id = $HOST
    }
    remote {
      auth = eap-mschapv2
      eap_id = %any
    }
    children {
      vola {
        local_ts = 0.0.0.0/0, ::/0
        esp_proposals = $ESP_PROPOSALS
        rekey_time = 0s
        life_time = 26h
        dpd_action = clear
      }
    }
  }
}

pools {
  vola-v4 {
    addrs = $pool4
    dns = $dns
  }
  # IPv6 is routed into the tunnel and dropped there, so it cannot leak around the VPN.
  vola-v6 {
    addrs = $pool6
  }
}
EOF
  chmod 644 "$SWAN_CONN"

  # Minimal logging: errors + connection up/down only, into a RAM-only journal namespace.
  cat >"$SWAN_LOGCONF" <<'EOF'
# managed by vola-server — minimal logging
charon-systemd {
  journal {
    default = 0
    ike_name = no
    enc = -1
    net = -1
    asn = -1
    lib = -1
    tls = -1
    esp = -1
    knl = -1
  }
}
EOF
  cat >"$JOURNAL_NS_CONF" <<'EOF'
# managed by vola-server — strongSwan logs live only in RAM and for at most about one day.
# MaxRetentionSec only deletes whole archived files, so MaxFileSec rotates the file hourly;
# without it the active file could hold connect records (client IP, user name) for weeks.
[Journal]
Storage=volatile
RuntimeMaxUse=16M
MaxFileSec=1h
MaxRetentionSec=1day
ForwardToSyslog=no
ForwardToWall=no
EOF
  unit=$(swan_unit)
  mkdir -p "/etc/systemd/system/$unit.d"
  cat >"/etc/systemd/system/$unit.d/vola.conf" <<EOF
# managed by vola-server
[Service]
LogNamespace=$JOURNAL_NS
EOF
  umask 077
  # apply a changed namespace config to an already running namespace journald
  systemctl try-restart "systemd-journald@$JOURNAL_NS.service" >/dev/null 2>&1 || true
  state_set SWAN_UNIT "$unit"
  write_secrets
  systemctl daemon-reload
  systemctl enable "$unit" >/dev/null 2>&1
  systemctl restart "$unit"
  local n=0
  until [[ -S /var/run/charon.vici || -S /run/charon.vici ]]; do
    n=$((n+1)); (( n > 20 )) && die "strongSwan did not start; see: journalctl --namespace=$JOURNAL_NS -u $unit"
    sleep 0.5
  done
  swanctl --load-all --noprompt >/dev/null
  ok "strongSwan running ($unit); connection 'vola' loaded"
}

harden_ssh() {
  say "SSH: key-only login"
  local found=0 f
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    if [[ -s $f ]] && grep -qE '^(ssh-|ecdsa-|sk-)' "$f"; then found=1; fi
  done
  if [[ $found -eq 0 ]]; then
    warn "no SSH authorized_keys found — leaving SSH settings unchanged to avoid locking you out"
    return 0
  fi
  umask 022
  cat >"$SSH_DROPIN" <<'EOF'
# managed by vola-server — keys only, no root login (loaded before cloud-init's 50-*/60-*.conf, so it wins)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  umask 077
  if sshd -t 2>/dev/null; then
    systemctl try-reload-or-restart ssh.service >/dev/null 2>&1 || systemctl try-reload-or-restart sshd.service >/dev/null 2>&1 || true
    ok "sshd: $(sshd -T 2>/dev/null | grep -E '^(passwordauthentication|permitrootlogin) ' | tr '\n' ' ' || echo 'passwordauthentication no')"
  else
    rm -f "$SSH_DROPIN"; warn "sshd config test failed; SSH settings left unchanged"
  fi
}

enable_unattended_upgrades() {
  say "Automatic security updates"
  umask 022
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  umask 077
  systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
  ok "unattended-upgrades enabled (security updates, no automatic reboot)"
}

self_install() {
  local src; src=$(readlink -f "$0")
  [[ -f $src && $(head -c 64 "$src") == '#!/usr/bin/env bash'* ]] \
    || die "run this script from a file (download it first), not through a pipe"
  if [[ $src != "$SELF_INSTALL" ]]; then
    install -m 755 "$src" "$SELF_INSTALL"
  fi
}

cmd_install() {
  HOST=""; EMAIL=""; CA=auto; ACME_SERVER=""; EAB_KID=""; EAB_HMAC=""
  local dns="" pool4="" pool6="" skip_dns=0 first_user="" label=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host)  HOST=${2:-}; shift 2 ;;
      --email) EMAIL=${2:-}; shift 2 ;;
      --ca)    CA=${2:-}; shift 2 ;;
      --acme-server)  ACME_SERVER=${2:-}; shift 2 ;;
      --eab-kid)      EAB_KID=${2:-}; shift 2 ;;
      --eab-hmac-key)
        EAB_HMAC=${2:-}; shift 2
        warn "--eab-hmac-key on the command line ends up in shell history and the sudo log; prefer the prompt or VOLA_EAB_HMAC" ;;
      --dns)   dns=${2:-}; shift 2 ;;
      --pool)  pool4=${2:-}; shift 2 ;;
      --no-dns-check) skip_dns=1; shift ;;
      --user)  first_user=${2:-}; shift 2
               valid_user "$first_user" || die "--user: a letter, then letters/digits/_/-, max 32 chars" ;;
      --name)  [[ $# -ge 2 ]] || die "--name needs a value"; label=$(check_label "$2"); shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  need_root
  check_os

  # Re-runs keep earlier choices unless overridden.
  [[ -z $HOST ]] && HOST=$(state_get HOST)
  [[ -z $EMAIL ]] && EMAIL=$(state_get EMAIL)
  dns=${dns:-$(state_get DNS)};     dns=${dns:-$DEFAULT_DNS}
  pool4=${pool4:-$(state_get POOL4)}; pool4=${pool4:-$DEFAULT_POOL4}
  pool6=$(state_get POOL6);         pool6=${pool6:-$DEFAULT_POOL6}
  [[ -n $EMAIL && ! $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] && die "invalid --email"
  [[ $CA == custom && -z $ACME_SERVER ]] && die "--ca custom needs --acme-server <url> (and usually --eab-kid)"
  if [[ -n $EAB_KID && -z $EAB_HMAC ]]; then
    # Secret input without a command line: environment (sudo --preserve-env=VOLA_EAB_HMAC),
    # otherwise the terminal (hidden) or one line on stdin.
    if [[ -n ${VOLA_EAB_HMAC:-} ]]; then EAB_HMAC=$VOLA_EAB_HMAC
    elif [[ -t 0 ]]; then read -rs -p "EAB HMAC key for $EAB_KID (input hidden): " EAB_HMAC; echo
    else IFS= read -r EAB_HMAC || true
    fi
    unset VOLA_EAB_HMAC
    [[ -n $EAB_HMAC ]] || die "--eab-kid needs the EAB HMAC key (prompt, stdin or VOLA_EAB_HMAC)"
  fi
  local d
  # shellcheck disable=SC2086
  for d in ${dns//,/ }; do valid_ipv4 "$d" || die "invalid DNS server '$d' (IPv4 addresses, comma separated)"; done
  local plen=${pool4##*/}
  # shellcheck disable=SC2015  # "valid, or die": the die is meant to run for any failure
  [[ $pool4 == */* && $plen =~ ^[0-9]{1,2}$ ]] && valid_ipv4 "${pool4%/*}" && (( plen >= 16 && plen <= 28 )) \
    || die "invalid --pool '$pool4' (e.g. 10.99.0.0/22)"

  install_packages

  say "Public address"
  local ip; ip=$(detect_public_ip) || die "could not detect this server's public IPv4 address"
  ok "public IPv4: $ip"
  if [[ -z $HOST ]]; then
    HOST="${ip//./-}.sslip.io"
    ok "no --host given; using $HOST (free wildcard DNS that maps the name to $ip)"
  fi
  HOST=${HOST,,}
  valid_fqdn "$HOST" || die "invalid host name '$HOST'"
  if [[ $skip_dns -eq 0 ]]; then
    resolves_to "$HOST" "$ip" || die "$HOST does not resolve to $ip (this server). Fix the DNS A record, or pass --no-dns-check if the server sits behind a static NAT that you know is right."
    ok "DNS: $HOST -> $ip"
  fi

  state_set KIT_VERSION "$KIT_VERSION"
  state_set HOST "$HOST"
  state_set EMAIL "$EMAIL"
  state_set PUBLIC_IP "$ip"
  state_set DNS "$dns"
  state_set POOL4 "$pool4"
  state_set POOL6 "$pool6"
  [[ -n $label ]] && state_set LABEL "$label"
  mkdir -p "$USERS_DIR"; chmod 700 "$STATE_DIR" "$USERS_DIR"

  self_install
  configure_sysctl
  configure_firewall
  obtain_certificate
  write_strongswan_config
  enable_unattended_upgrades
  harden_ssh

  echo
  say "Done. Server: $HOST"
  local n; n=$(find "$USERS_DIR" -maxdepth 1 -type f ! -name '.*' | wc -l)
  if [[ -n $first_user ]]; then
    if [[ -f $(user_file "$first_user") ]]; then
      echo "User '$first_user' already exists; its password is unchanged and not shown."
      show_line_qr "$first_user" "$(line_label)" "$HOST" || true
      echo "To include the password: sudo vola-server qr $first_user --with-password"
      echo "New password instead:    sudo vola-server user add $first_user --reset"
    else
      user_add "$first_user"
    fi
  elif (( n == 0 )); then
    echo "Next: create a VPN user —  sudo vola-server user add <name>"
  else
    echo "Existing users kept ($n). Show settings for one:  sudo vola-server client <name>"
  fi
  echo "Cloud firewall must allow inbound UDP 500 and UDP 4500 (and TCP 80 for certificate renewal)."
}

# ---------------------------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------------------------
reload_creds() {
  if [[ -S /var/run/charon.vici || -S /run/charon.vici ]]; then
    swanctl --load-creds --clear --noprompt >/dev/null
  fi
}

gen_password() { # 24 chars from [A-Za-z0-9] (~142 bits), easy to type on a phone
  local p=""
  while [[ ${#p} -lt 24 ]]; do p+=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9'); done
  printf '%s' "${p:0:24}"
}

user_add() {
  local name="" out="" reset=0 qr=1 label=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out=${2:-}; [[ -n $out ]] || die "--out needs a file path"; shift 2 ;;
      --reset) reset=1; shift ;;
      --no-qr) qr=0; shift ;;
      --name) [[ $# -ge 2 ]] || die "--name needs a value"; label=$(check_label "$2"); shift 2 ;;
      -*) die "unknown option: $1" ;;
      *) [[ -z $name ]] || die "only one user name"; name=$1; shift ;;
    esac
  done
  [[ -n $name ]] || die "usage: vola-server user add <name> [--out <file>] [--reset] [--no-qr] [--name <label>]"
  valid_user "$name" || die "user names: a letter, then letters/digits/_/-, max 32 chars"
  require_installed
  local f=$USERS_DIR/$name
  if [[ -f $f && $reset -eq 0 ]]; then die "user '$name' exists (use --reset to set a new password)"; fi

  local pw hash host
  pw=$(gen_password)
  hash=$(printf '%s' "$pw" | nt_hash)
  host=$(state_get HOST)
  local tmp; tmp=$(mktemp "$USERS_DIR/.u.XXXXXX")
  if [[ -n $hash ]]; then
    printf 'NTHASH=%s\nCREATED=%s\n' "$hash" "$(date -u +%Y-%m-%d)" >"$tmp"
  else
    # OpenSSL without MD4: fall back to storing the password (root-only file).
    warn "MD4 unavailable in OpenSSL; storing the password itself (root-only file) instead of its NT hash"
    printf 'EAP="%s"\nCREATED=%s\n' "$pw" "$(date -u +%Y-%m-%d)" >"$tmp"
  fi
  chmod 600 "$tmp"; mv "$tmp" "$f"
  write_secrets
  reload_creds

  if [[ -n $out ]]; then
    ( umask 077
      mkdir -p "$(dirname "$out")"
      printf "VOLA_HOST='%s'\nVOLA_REMOTE_ID='%s'\nVOLA_USERNAME='%s'\nVOLA_PASSWORD='%s'\n" \
        "$host" "$host" "$name" "$pw" >"$out" )
    chmod 600 "$out"
    ok "user '$name' $( ((reset)) && echo 'password reset' || echo 'created'); credentials written to $out (mode 600)"
  else
    ok "user '$name' $( ((reset)) && echo 'password reset' || echo 'created')"
    echo
    echo "  Server / Remote ID : $host"
    echo "  Username           : $name"
    echo "  Password           : $pw"
    echo
    echo "  This password is shown only once. The server keeps only its NT hash, which is"
    echo "  equivalent to the password for VPN login: keep /etc/vola-server and /etc/swanctl"
    echo "  out of backups and shared snapshots."
    if (( qr )); then
      # The password is known right now, so this is the one moment the kit can put it in a code.
      show_line_qr "$name" "$(line_label "$label")" "$host" "$pw" \
        || warn "no QR code shown; later: sudo vola-server qr $name --with-password"
    fi
  fi
  pw=""
}

user_del() {
  local name=${1:-}
  [[ -n $name ]] || die "usage: vola-server user del <name>"
  valid_user "$name" || die "invalid user name"
  require_installed
  [[ -f $USERS_DIR/$name ]] || die "no such user '$name'"
  rm -f "$USERS_DIR/$name"
  write_secrets
  reload_creds
  # Disconnect that user's live sessions.
  local id
  for id in $(swanctl --list-sas --ike vola 2>/dev/null | awk -v u="$name" '
      /^vola: #[0-9]+/ { id=$2; gsub(/[#,]/, "", id) }
      index($0, "EAP: '"'"'" u "'"'"'") { print id }' | sort -u); do
    swanctl --terminate --ike-id "$id" --force --timeout 5 >/dev/null 2>&1 || true
  done
  ok "user '$name' deleted"
}

user_list() {
  require_installed
  local f any=0
  shopt -s nullglob
  for f in "$USERS_DIR"/*; do valid_user "$(basename "$f")" && { basename "$f"; any=1; }; done
  shopt -u nullglob
  [[ $any -eq 1 ]] || echo "(no users)"
}

cmd_user() {
  need_root
  local sub=${1:-}; shift || true
  case "$sub" in
    add)  user_add "$@" ;;
    del|delete|rm) user_del "$@" ;;
    list|ls) user_list ;;
    *) die "usage: vola-server user add|del|list ..." ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# sharing: vola-line/1 links, QR codes, configuration profiles (DESIGN-2 §4.14.3, §4.15)
# ---------------------------------------------------------------------------------------------
user_file() { printf '%s/%s' "$USERS_DIR" "$1"; }

# --name value -> normalised label on stdout (dies on an invalid one)
check_label() {
  local raw=$1 l
  [[ ! $raw =~ [[:cntrl:]] ]] || die "--name: no control characters"
  l=$(norm_label "$raw")
  valid_label "$l" || die "--name: 1 to 32 characters"
  printf '%s' "$l"
}

# Label for a line: --name, else the one saved by `install --name`, else "My server".
line_label() {
  local l=${1:-}
  [[ -n $l ]] || l=$(state_get LABEL)
  printf '%s' "${l:-$DEFAULT_LABEL}"
}

# vola-line/1 link on stdout. stdin: name, host, rid, user, pw (one per line; pw may be empty).
# Keys in the fixed order v, name, host, rid, user, pw; every value is percent-encoded except
# the RFC 3986 unreserved characters (A-Z a-z 0-9 - . _ ~). Exit 3 if the link would be longer
# than LINE_MAX_BYTES. Values come on stdin so the password never appears in a command line.
line_url() {
  python3 -c '
import sys, urllib.parse
vals = sys.stdin.read().split("\n")
parts = ["v=1"]
for key, val in zip(("name", "host", "rid", "user", "pw"), vals):
    if val:
        parts.append(key + "=" + urllib.parse.quote(val, safe="", encoding="utf-8", errors="strict"))
link = "volavpn://line?" + "&".join(parts)
if len(link.encode("utf-8")) > int(sys.argv[1]):
    sys.exit(3)
sys.stdout.write(link + "\n")
' "$LINE_MAX_BYTES"
}

# user label host [password] -> link on stdout (the kit's lines always use Remote ID == host)
line_link() {
  local rc=0 link
  link=$(printf '%s\n%s\n%s\n%s\n%s\n' "$2" "$3" "$3" "$1" "${4:-}" | line_url) || rc=$?
  if (( rc == 3 )); then
    warn "this line is longer than $LINE_MAX_BYTES bytes, too long for a QR code; use: vola-server profile $1 --out <file>"
    return 1
  fi
  (( rc == 0 )) || { warn "could not build the line link (python3 missing?)"; return 1; }
  printf '%s\n' "$link"
}

# qrencode is in BASE_PKGS; servers installed with kit 1.0.x get it on first use.
ensure_qrencode() {
  have qrencode && return 0
  if [[ $EUID -eq 0 ]] && have apt-get; then
    say "Installing qrencode (draws QR codes in the terminal)"
    if ( umask 022; export DEBIAN_FRONTEND=noninteractive
         apt-get install -y -qq --no-install-recommends qrencode >/dev/null 2>&1 \
           || { apt-get update -qq && apt-get install -y -qq --no-install-recommends qrencode >/dev/null; } ); then
      if [[ -f $STATE_FILE ]] && ! grep -qw qrencode <<<"$(state_get PKGS_ADDED)"; then
        state_set PKGS_ADDED "$(state_get PKGS_ADDED) qrencode"
      fi
    fi
  fi
  have qrencode || { warn "qrencode is not installed (sudo apt-get install qrencode)"; return 1; }
}

# Draw a link as a terminal QR code (error correction M). The link goes in on stdin.
draw_qr() { printf '%s' "$1" | qrencode -t ANSIUTF8 -l M; }

# user label host [password]: QR code; without a password also the link text for copy/paste.
# With a password only the code is shown — never the link text or the password itself.
show_line_qr() {
  local link
  link=$(line_link "$1" "$2" "$3" "${4:-}") || return 1
  ensure_qrencode || return 1
  echo
  draw_qr "$link"
  if [[ -n ${4:-} ]]; then
    echo "  '$2' — user '$1', password included. Scan it with Vola or the iPhone Camera app."
    echo "  Anyone who scans this can use your server. Don't post it or keep a screenshot."
  else
    echo "  '$2' — user '$1', no password. Scan it with Vola or the iPhone Camera app,"
    echo "  or paste this link into Vola:"
    echo
    echo "  $link"
  fi
}

# Read a password for --with-password: hidden on a terminal, otherwise one line of stdin.
# Sets PW. The server keeps only a hash, so a password can be checked but never recovered.
read_password() {
  PW=""
  if [[ -t 0 ]]; then
    read -rs -p "Password for '$1' (input hidden): " PW || true; echo >&2
  else
    IFS= read -r PW || true
  fi
  [[ -n $PW ]] || die "no password given"
  (( ${#PW} <= 128 )) && [[ ! $PW =~ [[:cntrl:]] ]] || die "that password doesn't match user '$1'"
}

# user-file password -> 0 if the password is the one stored (NT hash, or EAP= without MD4)
password_matches() {
  local f=$1 pw=$2 stored
  stored=$(sed -n 's/^NTHASH=//p' "$f" | head -n1)
  if [[ -n $stored ]]; then
    local h; h=$(printf '%s' "$pw" | nt_hash)
    [[ -n $h && $h == "$stored" ]]
    return
  fi
  stored=$(sed -n 's/^EAP=//p' "$f" | head -n1)
  [[ -n $stored && $stored == "\"$pw\"" ]]
}

# Parse the common arguments of qr / profile: <user> [--with-password] [--name <label>] [--out f]
share_args() {
  S_USER=""; S_WITHPW=0; S_LABEL=""; S_OUT=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --with-password) S_WITHPW=1; shift ;;
      --name) [[ $# -ge 2 ]] || die "--name needs a value"; S_LABEL=$(check_label "$2"); shift 2 ;;
      --out)  S_OUT=${2:-}; [[ -n $S_OUT ]] || die "--out needs a file path"; shift 2 ;;
      -*) die "unknown option: $1" ;;
      *) [[ -z $S_USER ]] || die "only one user name"; S_USER=$1; shift ;;
    esac
  done
}

share_user_checked() { # -> dies unless S_USER names an existing user
  [[ -n $S_USER ]] || die "$1"
  valid_user "$S_USER" || die "invalid user name"
  [[ -f $(user_file "$S_USER") ]] || die "no such user '$S_USER' (create it: vola-server user add $S_USER)"
}

cmd_qr() {
  share_args "$@"
  [[ -z $S_OUT ]] || die "qr has no --out (to write a file, use: vola-server profile)"
  need_root; require_installed
  share_user_checked "usage: vola-server qr <name> [--with-password] [--name <label>]"
  local label host; label=$(line_label "$S_LABEL"); host=$(state_get HOST)
  if (( S_WITHPW )); then
    read_password "$S_USER"
    password_matches "$(user_file "$S_USER")" "$PW" || { PW=""; die "that password doesn't match user '$S_USER'"; }
    show_line_qr "$S_USER" "$label" "$host" "$PW" || { PW=""; die "no QR code shown"; }
    PW=""
  else
    show_line_qr "$S_USER" "$label" "$host" || die "no QR code shown"
  fi
}

# host user label out -> .mobileconfig (DESIGN-2 §4.15.4 template, same keys and values as the
# app's export). stdin: the password, or nothing. Written via a temp file (mode 600) + rename.
write_profile() {
  python3 -c '
import os, plistlib, sys, tempfile, uuid
host, user, label, out = sys.argv[1:5]
pw = sys.stdin.read().rstrip("\n")
ident = "vola.line.%s.%s" % (host, user)
ikev2 = {
    "RemoteAddress": host,
    "RemoteIdentifier": host,
    "LocalIdentifier": user,
    "AuthenticationMethod": "None",
    "ExtendedAuthEnabled": 1,
    "AuthName": user,
}
if pw:
    ikev2["AuthPassword"] = pw
sa = {"EncryptionAlgorithm": "AES-256", "IntegrityAlgorithm": "SHA2-256", "DiffieHellmanGroup": 19}
ikev2.update({
    "IKESecurityAssociationParameters": dict(sa),
    "ChildSecurityAssociationParameters": dict(sa),
    "EnablePFS": 1,
    "DeadPeerDetectionRate": "Medium",
    "OnDemandEnabled": 0,
})
vpn = {
    "PayloadType": "com.apple.vpn.managed",
    "PayloadVersion": 1,
    "PayloadDisplayName": label,
    "PayloadIdentifier": ident + ".vpn",
    "PayloadUUID": str(uuid.uuid4()).upper(),
    "UserDefinedName": label,
    "VPNType": "IKEv2",
    "IKEv2": ikev2,
    "IPv4": {"OverridePrimary": 1},
}
profile = {
    "PayloadType": "Configuration",
    "PayloadVersion": 1,
    "PayloadDisplayName": label,
    "PayloadIdentifier": ident,
    "PayloadUUID": str(uuid.uuid4()).upper(),
    "PayloadContent": [vpn],
}
data = plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)
d = os.path.dirname(os.path.abspath(out))
fd, tmp = tempfile.mkstemp(dir=d, prefix=".vola-profile.")
try:
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
except BaseException:
    try: os.unlink(tmp)
    except OSError: pass
    raise
' "$1" "$2" "$3" "$4"
}

cmd_profile() {
  share_args "$@"
  local usage="usage: vola-server profile <name> [--with-password] [--name <label>] --out <file.mobileconfig>"
  [[ -n $S_OUT ]] || die "--out <file.mobileconfig> is required (a profile is never printed to the terminal). $usage"
  need_root; require_installed
  share_user_checked "$usage"
  [[ ! -d $S_OUT ]] || die "--out is a directory; give a file name such as $S_USER.mobileconfig"
  local label host; label=$(line_label "$S_LABEL"); host=$(state_get HOST)
  ( umask 077; mkdir -p "$(dirname "$S_OUT")" )
  if (( S_WITHPW )); then
    read_password "$S_USER"
    password_matches "$(user_file "$S_USER")" "$PW" || { PW=""; die "that password doesn't match user '$S_USER'"; }
    printf '%s' "$PW" | write_profile "$host" "$S_USER" "$label" "$S_OUT"
    PW=""
  else
    write_profile "$host" "$S_USER" "$label" "$S_OUT" </dev/null
  fi
  # Under sudo, hand the file to the invoking user so it can be copied off the server.
  if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} && $EUID -eq 0 ]]; then
    chown "$SUDO_UID:$SUDO_GID" "$S_OUT" 2>/dev/null || true
  fi
  ok "profile '$label' for user '$S_USER' written to $S_OUT (mode 600, password $( ((S_WITHPW)) && echo included || echo 'not included: iOS asks for it when connecting'))"
  echo "This profile isn't signed; iOS shows it as \"Unverified\". AirDrop or mail it to the device, then finish in Settings."
  (( S_WITHPW )) && echo "Anyone who opens this file can use your server. The password is stored in the file as plain text."
  return 0
}

# ---------------------------------------------------------------------------------------------
# status / client / uninstall
# ---------------------------------------------------------------------------------------------
cmd_status() {
  need_root; require_installed
  local host unit cert sessions users
  host=$(state_get HOST); unit=$(state_get SWAN_UNIT); unit=${unit:-$(swan_unit)}
  cert=$SWAN_DIR/x509/vola.pem
  echo "${B}Vola VPN server${N}  (kit $(state_get KIT_VERSION))"
  echo "  Host / Remote ID : $host"
  echo "  strongSwan       : $(systemctl is-active "$unit" 2>/dev/null || true) ($unit)"
  echo "  Firewall unit    : $(systemctl is-active vola-firewall.service 2>/dev/null || true)"
  if iptables -w -C INPUT -j VOLA-IN 2>/dev/null && iptables -w -C FORWARD -j VOLA-FWD 2>/dev/null \
     && iptables -w -t nat -C POSTROUTING -j VOLA-POST 2>/dev/null; then
    echo "  Firewall rules   : present (INPUT, FORWARD, NAT)"
  else
    echo "  Firewall rules   : MISSING — run: sudo vola-server firewall-apply"
  fi
  echo "  IP forwarding    : $(sysctl -n net.ipv4.ip_forward)"
  if [[ -f $cert ]]; then
    echo "  Certificate      : $(openssl x509 -in "$cert" -noout -issuer | sed 's/^issuer=\s*//')"
    echo "  Cert expires     : $(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
  else
    echo "  Certificate      : MISSING"
  fi
  echo "  Auto-renewal     : certbot.timer $(systemctl is-active certbot.timer 2>/dev/null || true)"
  users=$(find "$USERS_DIR" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l)
  sessions=$(swanctl --list-sas --ike vola 2>/dev/null | grep -cE '^vola: #[0-9]+, ESTABLISHED' || true)
  echo "  Users            : $users"
  echo "  Connected now    : ${sessions:-0} session(s)"
  echo "  Listening        :"
  ss -Hlnup 2>/dev/null | awk '$4 ~ /:(500|4500)$/ {print "    udp " $4}' | sort -u
  echo "  Logs (RAM only)  : journalctl --namespace=$JOURNAL_NS -u $unit"
}

cmd_client() {
  local name="" json=0 label=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json) json=1; shift ;;
      --name) [[ $# -ge 2 ]] || die "--name needs a value"; label=$(check_label "$2"); shift 2 ;;
      -*) die "unknown option: $1" ;;
      *) [[ -z $name ]] || die "only one user name"; name=$1; shift ;;
    esac
  done
  need_root; require_installed
  [[ -n $name ]] || die "usage: vola-server client <name> [--json] [--name <label>]"
  valid_user "$name" || die "invalid user name"
  [[ -f $(user_file "$name") ]] || die "no such user '$name' (create it: vola-server user add $name)"
  local host dns
  host=$(state_get HOST); dns=$(state_get DNS)
  if (( json )); then client_json "$name" "$host" "$dns"; return; fi
  local link; link=$(line_link "$name" "$(line_label "$label")" "$host") || link="(unavailable)"
  cat <<EOF
IKEv2 settings for '$name'

  iPhone / iPad : Settings > General > VPN & Device Management > VPN > Add VPN Configuration
  Mac           : System Settings > VPN > Add VPN Configuration > IKEv2

    Type                 IKEv2
    Server               $host
    Remote ID            $host
    Local ID             (leave empty)
    User Authentication  Username
    Username             $name
    Password             (the password shown when the user was created)

  No certificate needs to be installed on the device: the server's certificate is issued
  by a public CA that Apple devices already trust.

Vola line (format vola-line/1, no password). Paste it into Vola, or show it as a QR code
with: sudo vola-server qr $name

$link
EOF
}

# Legacy machine-readable output (format vola-server/1, kit 1.0.x). No password.
client_json() { # name host dns
  local name=$1 host=$2 dns=$3 issuer
  issuer=$(openssl x509 -in "$SWAN_DIR/x509/vola.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=\s*//' || true)
  local dns_json
  # shellcheck disable=SC2086  # word splitting of the comma lists is intended
  dns_json=$(printf '"%s",' ${dns//,/ }); dns_json="[${dns_json%,}]"
  local ike_json esp_json
  # shellcheck disable=SC2086
  ike_json=$(printf '"%s",' ${IKE_PROPOSALS//,/ }); ike_json="[${ike_json%,}]"
  # shellcheck disable=SC2086
  esp_json=$(printf '"%s",' ${ESP_PROPOSALS//,/ }); esp_json="[${esp_json%,}]"
  printf '{"format":"vola-server/1","type":"ikev2","host":"%s","remote_id":"%s","local_id":"","username":"%s","user_auth":"eap-mschapv2","server_auth":"certificate","server_ca":"%s","dns":%s,"ike":{"recommended":{"encryption":"AES-256-GCM","integrity":"SHA2-256","dh_group":19,"lifetime_minutes":1440},"proposals":%s},"esp":{"recommended":{"encryption":"AES-256-GCM","integrity":"SHA2-256","pfs":false,"lifetime_minutes":1440},"proposals":%s}}\n' \
    "$host" "$host" "$name" "${issuer//\"/}" "$dns_json" "$ike_json" "$esp_json"
}

cmd_uninstall() {
  need_root
  local yes=0; [[ ${1:-} == --yes || ${1:-} == -y ]] && yes=1
  if [[ $yes -eq 0 ]]; then
    [[ -t 0 ]] || die "refusing to uninstall without --yes (non-interactive)"
    read -r -p "Remove the VPN server, its users, certificate and firewall rules? [y/N] " a
    [[ $a == [yY]* ]] || { echo "aborted"; exit 1; }
  fi
  local unit pkgs fwd
  unit=$(state_get SWAN_UNIT); unit=${unit:-$(swan_unit)}
  pkgs=$(state_get PKGS_ADDED); fwd=$(state_get IPFWD_BEFORE)

  say "Stopping services"
  swanctl --terminate --ike vola --force --timeout 5 >/dev/null 2>&1 || true
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  systemctl disable --now vola-firewall.service >/dev/null 2>&1 || true

  say "Removing firewall rules"
  firewall_remove
  if ufw_active; then
    ufw delete allow 500,4500/udp >/dev/null 2>&1 || true
    ufw delete allow 80/tcp >/dev/null 2>&1 || true
  fi
  firewall_persist

  say "Removing certificate and configuration"
  if have certbot; then certbot delete --cert-name "$CERT_NAME" --non-interactive >/dev/null 2>&1 || true; fi
  rm -f "$DEPLOY_HOOK" "$SWAN_CONN" "$SWAN_SECRETS" "$SWAN_LOGCONF" "$JOURNAL_NS_CONF" \
        "$SWAN_DIR/x509/vola.pem" "$SWAN_DIR/private/vola.key" "$SWAN_DIR"/x509ca/vola-chain-*.pem \
        "$FW_UNIT" "$SYSCTL_FILE" "$SSH_DROPIN"
  rm -rf "/etc/systemd/system/$unit.d/vola.conf"
  rmdir "/etc/systemd/system/$unit.d" 2>/dev/null || true
  systemctl daemon-reload
  sysctl -q -w net.ipv4.ip_forward="${fwd:-0}" || true
  if sshd -t 2>/dev/null; then systemctl try-reload-or-restart ssh.service >/dev/null 2>&1 || true; fi
  # drop the RAM-only strongSwan log namespace
  systemctl stop "systemd-journald@$JOURNAL_NS.service" "systemd-journald@$JOURNAL_NS.socket" >/dev/null 2>&1 || true
  rm -rf "/run/log/journal/"*".$JOURNAL_NS" 2>/dev/null || true

  if [[ -n $pkgs ]]; then
    say "Removing packages installed by the kit: $pkgs"
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $pkgs >/dev/null 2>&1 || warn "some packages could not be removed"
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq >/dev/null 2>&1 || true
  fi
  rm -rf "$STATE_DIR"
  rm -f "$SELF_INSTALL"
  ok "uninstalled. Close UDP 500/4500 and TCP 80 in your cloud firewall if nothing else uses them."
}

usage() {
  cat <<EOF
vola-server $KIT_VERSION — IKEv2 (username/password) VPN server for iPhone, iPad and Mac

Usage:
  sudo bash vola-server.sh install [--host <fqdn>] [--email <addr>]
        [--user <name>] [--name <label>]
        [--ca auto|letsencrypt|zerossl|custom] [--acme-server <url> --eab-kid <id>]
        (the EAB HMAC key is asked for, hidden, or read from stdin / VOLA_EAB_HMAC)
        [--dns 1.1.1.1,9.9.9.9] [--pool 10.99.0.0/22] [--no-dns-check]
  sudo vola-server user add <name> [--out <file>] [--reset] [--no-qr] [--name <label>]
  sudo vola-server user del <name>
  sudo vola-server user list
  sudo vola-server qr <name> [--with-password] [--name <label>]
  sudo vola-server profile <name> [--with-password] [--name <label>] --out <file.mobileconfig>
  sudo vola-server status
  sudo vola-server client <name> [--json] [--name <label>]
  sudo vola-server uninstall [--yes]

Without --host the server uses <public-ip-with-dashes>.sslip.io.
--name sets the line name shown in the Vola app (default "My server").
--with-password asks for the user's password (hidden) and checks it; the server can't recover it.
EOF
}

main() {
  local cmd=${1:-}; shift || true
  case "$cmd" in
    install)   cmd_install "$@" ;;
    user)      cmd_user "$@" ;;
    status)    cmd_status ;;
    client)    cmd_client "$@" ;;
    qr)        cmd_qr "$@" ;;
    profile)   cmd_profile "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    firewall-apply) need_root; require_installed; firewall_apply ;;   # used by vola-firewall.service
    version|--version) echo "$KIT_VERSION" ;;
    ""|-h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

# VOLA_KIT_LIB=1 loads the functions without running a command (used by server-kit/tests).
if [[ ${VOLA_KIT_LIB:-} != 1 ]]; then main "$@"; fi
