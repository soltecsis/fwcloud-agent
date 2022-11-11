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

  if [ $DIST = "Ubuntu" ]; then
    echo "(*) Adding the Suricata repository."
    add-apt-repository ppa:oisf/suricata-stable --yes
    if [ "$?" != "0" ]; then
      echo "Error: Adding Suricata repository"
      exit 1
    fi
    echo
  fi

  echo "(*) Updating packages lists."
  apt-get update  

  echo
  pkgInstall "suricata"

  echo "(*) Enabling Suricata service."
  systemctl enable suricata

  echo
  echo "(*) Setting up Suricata service."
  CFG_FILE="/etc/suricata/suricata.yaml"
  sed -i 's/community-id: false$/community-id: true/g' "$CFG_FILE"
  NETIF=`ip -p -j route show default | grep '"dev":' | awk -F'"' '{print $4}'`
  sed -i 's/interface: eth0$/interface: '$NETIF'/g' "$CFG_FILE"
  # For avoid error messages like this one:
  # [ERRCODE: SC_ERR_CONF_YAML_ERROR(242)] - App-Layer protocol sip enable status not set, so enabling by default. This behavior will change in Suricata 7, so please update your config. See ticket #4744 for more details.
  sed -z -i 's/    sip\:\n      \#enabled\: no/    sip\:\n      enabled\: no/g' "$CFG_FILE"
  sed -z -i 's/    rdp\:\n      \#enabled\: yes/    rdp\:\n      enabled\: no/g' "$CFG_FILE"
  sed -z -i 's/    mqtt\:\n      \# enabled\: no/    mqtt\:\n      enabled\: no/g' "$CFG_FILE"
  # Replace network interface in /etc/default/suricata
  sed -i 's/^IFACE=eth0$/IFACE='$NETIF'/g' /etc/default/suricata

  echo 
  echo "(*) Updating rules sources index."
  suricata-update update-sources

  echo 
  echo "(*) Enabling free rules sources."
  suricata-update enable-source oisf/trafficid
  suricata-update enable-source etnetera/aggressive
  suricata-update enable-source sslbl/ssl-fp-blacklist
  suricata-update enable-source et/open
  suricata-update enable-source tgreen/hunting
  suricata-update enable-source sslbl/ja3-fingerprints

  echo
  echo "(*) Updating rulesets."
  suricata-update

  echo 
  echo "(*) Starting Suricata."
  systemctl start suricata.service

  echo
}
################################################################

################################################################
disable() {
  pkgRemove "suricata"
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
