#!/bin/bash

#   Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
#   https://soltecsis.com
#   info@soltecsis.com
#
#
#   This file is part of FWCloud (https://fwcloud.net).
#
#   FWCloud is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   FWCloud is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with FWCloud.  If not, see <https://www.gnu.org/licenses/>.

. ./plugins/lib.sh
init

PLUGIN_NAME="crowdsec"
BOUNCER_NAME="fwcloud"
BOUNCER_CFG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
LAPI_CREDS="/etc/crowdsec/local_api_credentials.yaml"
CROWDSEC_CFG="/etc/crowdsec/config.yaml"

IPSET_V4="crowdsec-blacklists"
IPSET_V6="crowdsec6-blacklists"

MODE="$2"
LAPI_URL="$3"
MACHINE_CREDS_FILE="$4"

################################################################
install_repo() {
  if [ "$DIST" = "Ubuntu" ] || [ "$DIST" = "Debian" ]; then
    echo "(*) Adding CrowdSec repository."
    curl -s https://install.crowdsec.net | sudo sh
  elif [ "$DIST" = "CentOS" ] || [ "$DIST" = "Rocky" ]; then
    echo "(*) Adding CrowdSec repository."
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | sudo bash
  else
    echo "Error: Linux distribution not supported."
    echo "NOT_SUPPORTED"
    exit 1
  fi
}
################################################################

################################################################
install_common() {
  install_repo

  echo "(*) Installing CrowdSec."
  pkgInstall "crowdsec"

  echo "(*) Enabling CrowdSec."
  systemctl enable --now crowdsec

  echo "(*) Installing recommended base collections."
  cscli collections install crowdsecurity/linux || true
  cscli collections install crowdsecurity/sshd || true
  systemctl restart crowdsec
}
################################################################

################################################################
install_full() {
  install_common

  echo "(*) Installing CrowdSec firewall bouncer."
  pkgInstall "ipset"
  pkgInstall "crowdsec-firewall-bouncer-iptables"

  echo "(*) Creating FWCloud CrowdSec ipsets."
  ipset create "$IPSET_V4" hash:ip timeout 0 -exist
  ipset create "$IPSET_V6" hash:ip family inet6 timeout 0 -exist || true

  echo "(*) Registering FWCloud bouncer."
  API_KEY="$(cscli bouncers add "$BOUNCER_NAME" -o raw 2>/dev/null || true)"

  if [ -z "$API_KEY" ] && [ -f "$BOUNCER_CFG" ]; then
    API_KEY="$(grep '^api_key:' "$BOUNCER_CFG" | awk '{print $2}')"
  fi

  if [ -z "$API_KEY" ]; then
    echo "Error: Could not obtain CrowdSec bouncer API key."
    exit 1
  fi

  echo "(*) Writing FWCloud-compatible bouncer configuration."
  cat > "$BOUNCER_CFG" <<EOF
mode: ipset
update_frequency: 10s

log_mode: file
log_dir: /var/log/
log_level: info

api_url: http://127.0.0.1:8080/
api_key: $API_KEY

disable_ipv6: false
deny_action: DROP
deny_log: false

supported_decisions_types:
  - ban

blacklists_ipv4: $IPSET_V4
blacklists_ipv6: $IPSET_V6
ipset_type: hash:ip

# FWCloud owns the iptables rules.
# The bouncer only maintains these ipsets:
#   $IPSET_V4
#   $IPSET_V6
EOF

  systemctl enable --now crowdsec-firewall-bouncer
  systemctl restart crowdsec-firewall-bouncer

  echo "(*) Full CrowdSec installation completed."
  cscli bouncers list || true
}
################################################################

################################################################
install_agent() {
  if [ -z "$LAPI_URL" ] || [ -z "$MACHINE_CREDS_FILE" ]; then
    echo "Usage:"
    echo "$0 enable agent <lapi_url> <machine_credentials_file>"
    echo
    echo "Example:"
    echo "$0 enable agent https://10.0.0.1:8080 /tmp/webserver-local-api-credentials.yaml"
    exit 1
  fi

  install_common

  echo "(*) Removing firewall bouncer if present."
  systemctl disable --now crowdsec-firewall-bouncer || true
  pkgRemove "crowdsec-firewall-bouncer-iptables" || true
  pkgRemove "crowdsec-firewall-bouncer-nftables" || true
  pkgRemove "crowdsec-firewall-bouncer" || true

  echo "(*) Installing remote LAPI credentials."
  install -m 0600 "$MACHINE_CREDS_FILE" "$LAPI_CREDS"

  echo "(*) Setting LAPI URL."
  if command -v yq >/dev/null 2>&1; then
    yq -i ".url = \"$LAPI_URL\"" "$LAPI_CREDS"
  else
    sed -i "s|^url:.*|url: $LAPI_URL|" "$LAPI_CREDS"
  fi

  echo "(*) Restarting CrowdSec agent."
  systemctl restart crowdsec

  echo "(*) Agent-only CrowdSec installation completed."
  cscli lapi status || true
}
################################################################

################################################################
disable() {
  echo "(*) Disabling CrowdSec services."
  systemctl disable --now crowdsec-firewall-bouncer || true
  systemctl disable --now crowdsec || true

  echo "(*) Removing CrowdSec packages."
  pkgRemove "crowdsec-firewall-bouncer-iptables" || true
  pkgRemove "crowdsec-firewall-bouncer-nftables" || true
  pkgRemove "crowdsec-firewall-bouncer" || true
  pkgRemove "crowdsec" || true
}
################################################################

case "$1" in
  enable)
    case "$MODE" in
      full)
        install_full
        echo "ENABLED_FULL"
        ;;
      agent)
        install_agent
        echo "ENABLED_AGENT"
        ;;
      *)
        echo "Usage:"
        echo "$0 enable full"
        echo "$0 enable agent <lapi_url> <machine_credentials_file>"
        exit 1
        ;;
    esac
    ;;
  disable)
    disable
    echo "DISABLED"
    ;;
  *)
    echo "Usage:"
    echo "$0 enable full"
    echo "$0 enable agent <lapi_url> <machine_credentials_file>"
    echo "$0 disable"
    exit 1
    ;;
esac

exit 0
