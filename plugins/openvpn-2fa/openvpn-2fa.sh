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
OPENVPN_GA_DIR="${OPENVPN_DIR}/google-authenticator"
OPENVPN_2FA_SCRIPT="check_2fa.sh"
OPENVPN_2FA_SCRIPT_PATH="${OPENVPN_BIN_DIR}/${OPENVPN_2FA_SCRIPT}"
SERVER_CN="$2"
OPENVPN_SERVER_USERS_FILE=""
OPENVPN_SERVER_GA_DIR=""

if [ -n "$SERVER_CN" ]; then
  OPENVPN_SERVER_USERS_FILE="${OPENVPN_DIR}/${SERVER_CN}_2fa_users.txt"
  OPENVPN_SERVER_GA_DIR="${OPENVPN_GA_DIR}/${SERVER_CN}"
fi

enable() {
  if [ -z "$SERVER_CN" ]; then
    echo "Error: Missing server CN."
    exit 1
  fi

  if [ $DIST = "RedHat" -o $DIST = "Rocky" ]; then
    pkgInstall "epel-release"
    pkgInstall "oathtool"
  else
    pkgInstall "oathtool"
  fi

  mkdir -p "$OPENVPN_DIR"
  mkdir -p "$OPENVPN_BIN_DIR"
  mkdir -p "${OPENVPN_GA_DIR}"
  mkdir -p "${OPENVPN_SERVER_GA_DIR}"
  touch "${OPENVPN_SERVER_USERS_FILE}"
  cp "./plugins/openvpn-2fa/${OPENVPN_2FA_SCRIPT}" "$OPENVPN_2FA_SCRIPT_PATH"
  chmod 755 "$OPENVPN_BIN_DIR"
  chmod 755 "$OPENVPN_2FA_SCRIPT_PATH"
  chmod 755 "${OPENVPN_GA_DIR}"
  chmod 755 "${OPENVPN_SERVER_GA_DIR}"
  chmod 644 "${OPENVPN_SERVER_USERS_FILE}"
}
################################################################

################################################################
disable() {
  if [ -n "$SERVER_CN" ]; then
    if [ -f "${OPENVPN_SERVER_USERS_FILE}" ]; then
      echo "Deleting ${OPENVPN_SERVER_USERS_FILE}"
      rm -f "${OPENVPN_SERVER_USERS_FILE}"
    fi

    if [ -d "${OPENVPN_SERVER_GA_DIR}" ]; then
      echo "Deleting ${OPENVPN_SERVER_GA_DIR}"
      rm -rf "${OPENVPN_SERVER_GA_DIR}"
    fi

    if [ -d "${OPENVPN_GA_DIR}" ] && [ -z "$(find "${OPENVPN_GA_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)" ]; then
      if [ -f "$OPENVPN_2FA_SCRIPT_PATH" ]; then
        echo "Deleting $OPENVPN_2FA_SCRIPT_PATH"
        rm -f "$OPENVPN_2FA_SCRIPT_PATH"
      fi

      rmdir "${OPENVPN_GA_DIR}" 2>/dev/null || true
      rmdir "$OPENVPN_BIN_DIR" 2>/dev/null || true

      if [ $DIST = "RedHat" -o $DIST = "Rocky" ]; then
        pkgRemove "oathtool"
      else
        pkgRemove "oathtool"
      fi
    fi

    return 0
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
