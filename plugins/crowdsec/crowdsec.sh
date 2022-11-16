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
    echo "(*) Adding the CrowdSec repository."
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
    if [ "$?" != "0" ]; then
      echo "Error: Adding CrowdSec repository"
      exit 1
    fi

    echo
    pkgInstall "crowdsec"
    pkgInstall "crowdsec-firewall-bouncer-iptables"
  elif [ $DIST = "CentOS" -o $DIST = "Rocky" ]; then
    echo "(*) Adding the CrowdSec repository."
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | sudo bash
    if [ "$?" != "0" ]; then
      echo "Error: Adding CrowdSec repository"
      exit 1
    fi

    echo
    echo "(*) Installing CrowdSec packages."
    pkgInstall "crowdsec"
    pkgInstall "crowdsec-firewall-bouncer-iptables"
  else
    echo "Error: Linux distribution not supported."
    echo "NOT_SUPPORTED"
    exit 1
  fi
}
################################################################

################################################################
disable() {
  pkgRemove "crowdsec-firewall-bouncer-iptables"
  pkgRemove "crowdsec"
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
