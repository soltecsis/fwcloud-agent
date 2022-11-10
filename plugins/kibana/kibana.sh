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
    pkgInstall "kibana" 

    echo "(*) Enabling Kibana service."
    systemctl daemon-reload
    systemctl enable kibana

    echo
    echo "(*) Kibana setup."
    KIBANA_CFG="/etc/kibana/kibana.yml"
    KIBANA_PORT="5601"
    sed -i "s/^#server.port\: '$KIBANA_PORT'$/server.port: '$KIBANA_PORT'/g" "$KIBANA_CFG"
    sed -i "s/^#server.host\: \"localhost\"$/#server.host\: \"localhost\"\nserver.host\: \"0.0.0.0\"/g" "$KIBANA_CFG"
    
    echo
    echo "(*) Starting Kibana service."
    systemctl start kibana

    echo
    echo "(*) Waiting for Kibana service start up."
    waitForTcpPort "$KIBANA_PORT" "Kibana" 120

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
  pkgRemove "kibana" 
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
