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
    pkgInstall "logstash"

    echo "(*) Enabling Logstash service."
    systemctl daemon-reload
    systemctl enable logstash

    echo
    echo "(*) Logstash setup."
    usermod -a -G adm logstash
    /usr/share/logstash/bin/logstash-plugin update >/dev/null 2>&1 &

    echo
    echo "(*) Starting Logstash service."
    systemctl start logstash

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
  pkgRemove "logstash"
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
