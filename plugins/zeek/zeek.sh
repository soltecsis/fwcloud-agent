#!/bin/bash

#   Copyright 2022 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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
enable() {
  if [ $DIST != "Ubuntu" -a $DIST != "Debian" ]; then
    echo "Error: Linux distribution not supported. Only Ubuntu and Debian are supported."
    echo "NOT_SUPPORTED"
    exit 1
  fi

  echo "(*) Adding the Zeek repository."
  MAJMIN=`echo $RELEASE | cut -c1-5`
  echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${MAJMIN}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
  curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${MAJMIN}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
  apt-get update

  echo
  echo "postfix postfix/mailname string example.com" | debconf-set-selections
  echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
  pkgInstall "postfix"

  pkgInstall "zeek"

  echo "(*) Setting up Zeek."
  CFG_FILE="/opt/zeek/etc/node.cfg"
  NETIF=`ip -p -j route show default | grep '"dev":' | awk -F'"' '{print $4}'`
  sed -i 's/interface=eth0/interface='$NETIF'/g' "$CFG_FILE"

  echo
  echo "(*) Starting Zeek."
  cp ./plugins/zeek/zeek.service /etc/systemd/system/    
  systemctl enable zeek
  /opt/zeek/bin/zeekctl install
  systemctl start zeek

  echo
}
################################################################

################################################################
disable() {
  pkgRemove "zeek"
}
################################################################


if [ "$1" = "enable" ]; then
  enable
  echo "ENABLED"
else
  disable
  echo "DISABLED"
fi

exit 0
