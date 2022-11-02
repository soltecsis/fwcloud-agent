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
    suricata-update enable-source etnetera/aggressive
    suricata-update enable-source sslbl/ssl-fp-blacklist
    suricata-update enable-source et/open
    suricata-update enable-source tgreen/hunting
    suricata-update enable-source sslbl/ja3-fingerprints
    suricata-update enable-source ptresearch/attackdetection

    echo
    echo "(*) Updating rulesets."
    suricata-update

    echo 
    echo "(*) Starting Suricata."
    systemctl start suricata.service

    echo
    echo "(*) Adding the Zeek repository."
    MAJMIN=`echo $RELEASE | cut -c1-5`
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${MAJMIN}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${MAJMIN}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    apt-get update
    
    pkgInstall "zeek"

    echo
    echo "(*) Setting up Zeek."
    CFG_FILE="/opt/zeek/etc/node.cfg"
    NETIF=`ip -p -j route show default | grep '"dev":' | awk -F'"' '{print $4}'`
    sed -i 's/interface=eth0/interface='$NETIF'/g' "$CFG_FILE"

    echo
    echo "(*) Starting Zeek."
    cp ./plugins/suricata/zeek.service /etc/systemd/system/    
    systemctl enable zeek
    /opt/zeek/bin/zeekctl install
    systemctl start zeek

    echo
    echo "(*) Installing ELK (Elastisearch Logstash Kibana) and Filebeat."
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update
    echo
    pkgInstall "elasticsearch"
    pkgInstall "kibana" 
    pkgInstall "logstash"
    pkgInstall "filebeat"

    echo
    echo "(*) Filebeat setup."
    filebeat modules enable suricata
    filebeat modules enable zeek
    filebeat modules enable system
    /usr/share/filebeat/bin/filebeat setup
    filebeat setup --pipelines --modules suricata, zeek, system
    CFG_FILE="/etc/filebeat/filebeat.yml"
    sed -i 's/hosts\: \[\"localhost\:9200\"\]/#hosts\: \[\"localhost\:9200\"\]/g' "$CFG_FILE"
    sed -i 's/#hosts\: \[\"localhost\:5044\"\]/hosts\: \[\"localhost\:5044\"\]/g' "$CFG_FILE"

    echo
    echo "(*) Creating logstash input config."
    cp ./plugins/suricata/filebeat-input.conf /etc/logstash/conf.d/

    echo
    echo "(*) Logstash setup."
    usermod -a -G adm logstash
    /usr/share/logstash/bin/logstash-plugin update

    echo
    echo "(*) Kibana setup."
    KIBANA_CFG="/etc/kibana/kibana.yml"
    echo >> "$KIBANA_CFG"
    echo "server.port: 5601" >> "$KIBANA_CFG"
    echo "server.host: \"0.0.0.0\"" >> "$KIBANA_CFG"
    
    echo
    echo "(*) Enabling ELK services."
    systemctl daemon-reload
    echo "Elastiksearch ..."
    systemctl enable elasticsearch.service
    echo "Kibana ..."
    systemctl enable kibana.service
    echo "Logstash ..."
    systemctl enable logstash.service
    echo "Filebeat ..."
    systemctl enable filebeat.service

    echo
    echo "(*) Restarting ELK services."
    echo "Elasticsearch ..."
    systemctl restart elasticsearch.service
    echo "Kibana ..."
    systemctl restart kibana.service
    echo "Logstash ..."
    systemctl restart logstash.service
    echo "Filebeat ..."
    systemctl restart filebeat.service

    echo
  else
    echo "ERROR: Linux distribution not supported."
    echo "NOT_SUPORTED"
    exit 1
  fi
}
################################################################

################################################################
disable() {
  pkgRemove "filebeat"
  pkgRemove "logstash"
  pkgRemove "kibana" 
  pkgRemove "elasticsearch"
  pkgRemove "zeek"
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
