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
    echo "(*) Adding the Elasticsearch repository."
    echo -n "Importing Elasticsearch GPG key ... "
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE="1" apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update
    echo
    pkgInstall "elasticsearch"

    echo "(*) Enabling Elasticsearch service."
    echo "Increase systemctl start timeout"
    mkdir /etc/systemd/system/elasticsearch.service.d
    echo "[Service]" > /etc/systemd/system/elasticsearch.service.d/startup-timeout.conf
    echo "TimeoutStartSec=600" >> /etc/systemd/system/elasticsearch.service.d/startup-timeout.conf
    echo "Enable service"
    systemctl daemon-reload
    systemctl enable elasticsearch

    echo
    echo "(*) Starting Elasticsearch service."
    systemctl start elasticsearch

    echo
    echo "(*) Elasticsearch setup."
    echo "Reset the password of the elastic built-in superuser"
    ES_USER="elastic"
    N_TRY=5
    while [ $N_TRY -gt 0 ]; do
      ES_PASS=`/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b 2>/dev/null | tail -n 1 | awk '{print $3}'`
      if [ -z "$ES_PASS" ]; then
        sleep 1
      else
        break
      fi
      N_TRY=`expr $N_TRY - 1`
      if [ $N_TRY = 0 ]; then
        /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b
      fi
    done

    echo "Generate an enrollment token for Kibana instances"
    KIBANA_TOKEN=`/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana`

    echo
    echo "(*) Elasticsearch access data."
    echo "Username: $ES_USER"
    echo "Password: $ES_PASS"
    echo "Kibana enrollement token: $KIBANA_TOKEN"

    echo
  else
    echo "Error: Linux distribution not supported."
    echo "NOT_SUPPORTED"
    exit 1
  fi
}
################################################################

################################################################
disable() {
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
