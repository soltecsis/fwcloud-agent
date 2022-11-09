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
    pkgInstall "filebeat"

    echo "(*) Setting up Filebeat service."
    CFG_FILE="/etc/filebeat/filebeat.yml"
    sed -i 's/^  #protocol: \"https\"$/  protocol: \"https\"\n  ssl.verification_mode: none/g' "$CFG_FILE"

    echo
    echo "(*) Enabling Filebeat service."
    systemctl daemon-reload
    systemctl enable filebeat

    echo
    NETIF=`ip -p -j route show default | grep '"dev":' | awk -F'"' '{print $4}'`
    FPROBE_PORT="2055"
    echo "fprobe fprobe/interface string ${NETIF}" | debconf-set-selections
    echo "fprobe fprobe/collector string localhost:${FPROBE_PORT}" | debconf-set-selections
    pkgInstall "fprobe"

    echo "(*) Enabling Fprobe service."
    systemctl daemon-reload
    systemctl enable fprobe

    echo
    echo "(*) Starting Fprobe service."
    systemctl start fprobe

    echo
    echo "(*) Enabling filebeat modules."
    MODULES_DIR="/etc/filebeat/modules.d"
    MODULES="suricata zeek netflow"
    for MODULE in $MODULES; do
      filebeat modules enable $MODULE
      sed -i 's/^    enabled: false$/    enabled: true/g' "${MODULES_DIR}/${MODULE}.yml"
    done

    echo
    echo "(*) Final steps."
    echo "WARNING: This steps must be accomplished manually in the destination server."
    echo "- Set up the hosts, username and password parameters of the output.elasticsearch section"
    echo "  for your Elasticsearch server in the /etc/filebeat/filebeat.yml configuration file."
    echo "- Check the Filebeat config file with: filebeat test config"
    echo "- Verify the Filebeat-Elasticsearch communication with: filebeat test output"
    echo "- Run the command: /usr/share/filebeat/bin/filebeat setup"
    echo "- Start Filebeat with: systemctl start filebeat"

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
  pkgRemove "fprobe"
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
