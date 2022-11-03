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
    echo "(*) Installing ELK (Elastisearch Logstash Kibana) and Filebeat."
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update
    echo
    pkgInstall "elasticsearch"
    pkgInstall "kibana" 
    pkgInstall "logstash"

    echo "(*) Enabling ELK services."
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl enable kibana
    systemctl enable logstash

    echo
    echo "(*) Elasticsearch setup."
    # Enable Elasticsearch security setup.
    CFG_FILE="/etc/elasticsearch/elasticsearch.yml"
    echo >> "$CFG_FILE"
    #echo "xpack.security.enabled: true" >> "$CFG_FILE"
    echo "xpack.security.authc.api_key.enabled: true" >> "$CFG_FILE"
    # Add user.
    ES_USER="admin"
    passGen 32
    ES_PASS="$PASSGEN"
    /usr/share/elasticsearch/bin/elasticsearch-users useradd $ES_USER -p $ES_PASS -r superuser
    # Setup for only one node cluster.
    curl -u $ES_USER:$ES_PASS -X PUT http://localhost:9200/_template/default -H 'Content-Type: application/json' -d '{"index_patterns": ["*"],"order": -1,"settings": {"number_of_shards": "1","number_of_replicas": "0"}}'
    curl -u $ES_USER:$ES_PASS -X PUT http://localhost:9200/_settings -H 'Content-Type: application/json' -d '{"index": {"number_of_shards": "1","number_of_replicas": "0"}}'
    # Increase systemctl start timeout.
    mkdir /etc/systemd/system/elasticsearch.service.d
    echo "[Service]" > /etc/systemd/system/elasticsearch.service.d/startup-timeout.conf
    echo "TimeoutStartSec=600" >> /etc/systemd/system/elasticsearch.service.d/startup-timeout.conf
    systemctl daemon-reload

    echo
    echo "(*) Creating logstash input config."
    sed 's/ES_USER/'$ES_USER'/g' ./plugins/suricata/filebeat-input.conf | sed 's/ES_PASS/'$ES_PASS'/g' > /etc/logstash/conf.d/filebeat-input.conf

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

    echo
    echo "(*) Starting unattended-upgrades."
    systemctl start unattended-upgrades

    echo
    echo "(*) Elasticsearch access data:"
    echo "USER: $ES_USER"
    echo "PASS: $ES_PASS"
    echo "Kibana enrollement token: `/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana`"
    echo "Kibana verification code: `/usr/share/kibana/bin/kibana-verification-code`"

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
  pkgRemove "logstash"
  pkgRemove "kibana" 
  pkgRemove "elasticsearch"
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
