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
    # Stop unattended-upgrades in order to avoid interferences with the installation process.
    echo "(*) Stopping unattended-upgrades."
    systemctl stop unattended-upgrades

    echo
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

    echo "(*) Enabling ELK services."
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl enable kibana
    systemctl enable logstash
    systemctl enable filebeat

    echo
    echo "(*) Filebeat setup."
    filebeat modules enable suricata
    filebeat modules enable zeek
    /usr/share/filebeat/bin/filebeat setup
    filebeat setup --pipelines --modules suricata, zeek
    CFG_FILE="/etc/filebeat/filebeat.yml"
    sed -i 's/^output.elasticsearch\:$/#output.elasticsearch\:/g' "$CFG_FILE"
    sed -i 's/^  hosts\: \[\"localhost\:9200\"\]$/  #hosts\: \[\"localhost\:9200\"\]/g' "$CFG_FILE"
    sed -i 's/^#output.logstash\:$/  output.logstash\:/g' "$CFG_FILE"
    sed -i 's/#hosts\: \[\"localhost\:5044\"\]/hosts\: \[\"localhost\:5044\"\]/g' "$CFG_FILE"

    echo
    echo "(*) Elasticksearch setup."
    # Enable Elasticsearch security setup.
    CFG_FILE="/etc/elasticsearch/elasticsearch.yml"
    echo >> "$CFG_FILE"
    echo "xpack.security.enabled: true" >> "$CFG_FILE"
    echo "xpack.security.authc.api_key.enabled: true" >> "$CFG_FILE"
    # Add user.
    passGen 32
    ELASTIC_PASS="$PASSGEN"
    /usr/share/elasticsearch/bin/elasticsearch-users useradd elastic -p $ELASTIC_PASS -r superuser
    # Setup for only one node cluster.
    curl -u elastic:$ELASTIC_PASS -X PUT http://localhost:9200/_template/default -H 'Content-Type: application/json' -d '{"index_patterns": ["*"],"order": -1,"settings": {"number_of_shards": "1","number_of_replicas": "0"}}'
    curl -u elastic:$ELASTIC_PASS -X PUT http://localhost:9200/_settings -H 'Content-Type: application/json' -d '{"index": {"number_of_shards": "1","number_of_replicas": "0"}}'
    # Increase systemctl start timeout.
    mkdir /etc/systemd/system/elasticsearch.service.d
    echo "[Service]" > /etc/systemd/system/elasticsearch.service.d/startup-timeout.conf
    echo "TimeoutStartSec=600" >> /etc/systemd/system/elasticsearch.service.d/startup-timeout.conf
    systemctl daemon-reload

    echo
    echo "(*) Creating logstash input config."
    sed 's/GENERATED_PASSWORD/'$ELASTIC_PASS'/g' ./plugins/suricata/filebeat-input.conf > /etc/logstash/conf.d/filebeat-input.conf

    echo
    echo "(*) Logstash setup."
    usermod -a -G adm logstash
    /usr/share/logstash/bin/logstash-plugin update >/dev/null 2>&1 &

    echo
    echo "(*) Kibana setup."
    KIBANA_CFG="/etc/kibana/kibana.yml"
    echo >> "$KIBANA_CFG"
    echo "server.port: 5601" >> "$KIBANA_CFG"
    echo "server.host: \"0.0.0.0\"" >> "$KIBANA_CFG"
    
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
    echo "(*) Starting unattended-upgrades."
    systemctl start unattended-upgrades

    echo
    echo "(*) Elasticsearch access data:"
    echo "USER: elastic"
    echo "PASS: $ELASTIC_PASS"
    echo "Kibana enrollement token: `/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana`"

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
