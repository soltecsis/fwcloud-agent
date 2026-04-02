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

################################################################
find_openvpn_auth_pam_plugin() {
  for plugin_path in \
    /usr/lib/openvpn/openvpn-plugin-auth-pam.so \
    /usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so \
    /usr/lib64/openvpn/openvpn-plugin-auth-pam.so \
    /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so
  do
    if [ -f "$plugin_path" ]; then
      echo "$plugin_path"
      return 0
    fi
  done

  if [ "$DIST" = "Debian" -o "$DIST" = "Ubuntu" ]; then
    plugin_path=`dpkg -L openvpn 2>/dev/null | grep 'openvpn-plugin-auth-pam\.so$' | head -n 1`
    if [ -n "$plugin_path" ]; then
      echo "$plugin_path"
      return 0
    fi
  elif [ "$DIST" = "RedHat" -o "$DIST" = "CentOS" -o "$DIST" = "Fedora" -o "$DIST" = "Rocky" ]; then
    plugin_path=`rpm -ql openvpn 2>/dev/null | grep 'openvpn-plugin-auth-pam\.so$' | head -n 1`
    if [ -n "$plugin_path" ]; then
      echo "$plugin_path"
      return 0
    fi
  fi

  plugin_path=`find /usr/lib /usr/lib64 -name 'openvpn-plugin-auth-pam.so' 2>/dev/null | head -n 1`
  if [ -n "$plugin_path" ]; then
    echo "$plugin_path"
    return 0
  fi

  return 1
}
################################################################

################################################################
info() {
  PLUGIN_PATH=`find_openvpn_auth_pam_plugin`
  if [ -z "$PLUGIN_PATH" ]; then
    echo "Error: Unable to locate openvpn-plugin-auth-pam.so."
    exit 1
  fi

  echo "PAM_PLUGIN_PATH=$PLUGIN_PATH"
}
################################################################

################################################################
enable() {
  if [ $DIST = "RedHat" -o $DIST = "Rocky" ]; then
    pkgInstall "epel-release"
    pkgInstall "google-authenticator"
  else
    pkgInstall "libpam-google-authenticator"
  fi

  cp ./plugins/openvpn-2fa/pam-openvpn /etc/pam.d/openvpn

  if [ ! -f /etc/openvpn/2fa_users.txt ]; then
    mkdir -p /etc/openvpn
    touch /etc/openvpn/2fa_users.txt
    chmod 600 /etc/openvpn/2fa_users.txt
  fi

  mkdir -p /etc/openvpn/google-authenticator
  chmod 700 /etc/openvpn/google-authenticator
}
################################################################

################################################################
disable() {
  if [ -f /etc/pam.d/openvpn ]; then
    rm -f /etc/pam.d/openvpn
    echo "Deleting /etc/pam.d/openvpn"
  fi

  if [ -f /etc/openvpn/2fa_users.txt ]; then
    rm -f /etc/openvpn/2fa_users.txt
    echo "Deleting /etc/openvpn/2fa_users.txt"
  fi

  if [ -d /etc/openvpn/google-authenticator ]; then
    rm -rf /etc/openvpn/google-authenticator
    echo "Deleting /etc/openvpn/google-authenticator"
  fi

  if [ $DIST = "RedHat" -o $DIST = "Rocky" ]; then
    pkgRemove "google-authenticator"
  else
    pkgRemove "libpam-google-authenticator"
  fi
}
################################################################


if [ "$1" = "enable" ]; then
  enable
  echo "ENABLED"
elif [ "$1" = "info" ]; then
  info
  echo "INFO"
elif [ "$1" = "disable" ]; then
  disable
  echo "DISABLED"
else
  echo "Error: Invalid action '$1'."
  exit 1
fi

exit 0
