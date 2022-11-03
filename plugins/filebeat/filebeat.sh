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
    pkgInstall "filebeat"

    echo "(*) Enabling Filebeat services."
    systemctl daemon-reload
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
    echo "(*) Restarting Filebeat services."
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
