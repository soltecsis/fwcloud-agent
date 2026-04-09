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

OPENVPN_DIR="/etc/openvpn"
OPENVPN_BIN_DIR="${OPENVPN_DIR}/bin"
OPENVPN_2FA_SCRIPT="check_2fa.sh"
OPENVPN_2FA_SCRIPT_PATH="${OPENVPN_BIN_DIR}/${OPENVPN_2FA_SCRIPT}"

enable() {
  if [ $DIST = "RedHat" -o $DIST = "Rocky" ]; then
    pkgInstall "epel-release"
    pkgInstall "oathtool"
  else
    pkgInstall "oathtool"
  fi

  mkdir -p "$OPENVPN_DIR"
  mkdir -p "$OPENVPN_BIN_DIR"
  mkdir -p "${OPENVPN_DIR}/google-authenticator"
  cp "./plugins/openvpn-2fa/${OPENVPN_2FA_SCRIPT}" "$OPENVPN_2FA_SCRIPT_PATH"
  chmod 755 "$OPENVPN_BIN_DIR"
  chmod 700 "$OPENVPN_2FA_SCRIPT_PATH"
  chmod 700 "${OPENVPN_DIR}/google-authenticator"
}
################################################################

################################################################
disable() {
  if [ -f "$OPENVPN_2FA_SCRIPT_PATH" ]; then
    rm -f "$OPENVPN_2FA_SCRIPT_PATH"
    echo "Deleting $OPENVPN_2FA_SCRIPT_PATH"
  fi

  if [ -d "${OPENVPN_DIR}/google-authenticator" ]; then
    rm -rf "${OPENVPN_DIR}/google-authenticator"
    echo "Deleting ${OPENVPN_DIR}/google-authenticator"
  fi

  if [ $DIST = "RedHat" -o $DIST = "Rocky" ]; then
    pkgRemove "oathtool"
  else
    pkgRemove "oathtool"
  fi
}
################################################################


if [ "$1" = "enable" ]; then
  enable
  echo "ENABLED"
elif [ "$1" = "disable" ]; then
  disable
  echo "DISABLED"
else
  echo "Error: Invalid action '$1'."
  exit 1
fi

exit 0
