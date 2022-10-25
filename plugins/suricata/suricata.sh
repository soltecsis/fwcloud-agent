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
  if [ $DIST = "Ubuntu" -o $DIST = "Debian" ]; then
    echo "(*) Adding the Suricata repository."
    add-apt-repository ppa:oisf/suricata-stable --yes
    if [ "$?" != "0" ]; then
      echo "Error: Adding Suricata repository"
      exit 1
    fi
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
    
    echo 
    echo "(*) Updating rules sources index."
    suricata-update update-sources

    echo 
    echo "(*) Enabling free rules sources."
    suricata-update enable-source oisf/trafficid
    suricata-update enable-source sslbl/ssl-fp-blacklist

    echo
    echo "(*) Updating rulesets."
    suricata-update

    echo 
    echo "(*) Starting Suricata."
    systemctl start suricata.service

    echo
    echo "(*) Installing ELK (Elastisearch Logstash Kibana)."
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update
    pkgInstall "elasticsearch"
    pkgInstall "kibana" 
    pkgInstall "logstash"

    echo
    echo "(*) Creating logstash input/outpu config."
    cp ./plugins/suricata/10-input.conf /etc/logstash/conf.d/
    cp ./plugins/suricata/30-outputs.conf /etc/logstash/conf.d/

    echo
    echo "(*) Enabling ELK services."
    systemctl daemon-reload
    systemctl enable elasticsearch.service
    systemctl enable kibana.service
    systemctl enable logstash.service

    echo
    echo "(*) Restarting ELK services."
    systemctl restart elasticsearch.service
    systemctl restart kibana.service
    systemctl restart logstash.service
  else
    echo "ERROR: Linux distribution not supported."
    echo "NOT_SUPORTED"
    exit 1
  fi
}
################################################################

################################################################
disable() {
  pkgInstall "logstash"
  pkgInstall "kibana" 
  pkgInstall "elasticsearch"
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
