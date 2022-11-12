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
notSupported() {
  echo "Error: Your Linux distribution ($DIST $RELEASE) is not supported."
  echo "Error: Only Debian 11 is supported for this plugin."
  echo "NOT_SUPPORTED"
  exit 1
}
################################################################

################################################################
enable() {
  MAJ=`echo $RELEASE | cut -c1-2`
  if [ $DIST != "Debian" ]; then
    notSupported
  elif [ $DIST = "Debian" -a $RELEASE != "bullseye" ]; then
    notSupported
  fi

  # https://dnssafety.diladele.com/docs/install/debian11/dns/
  
  echo "(*) Updating packages lists."
  apt-get update 

  pkgInstall "wget" 

  echo
  echo "(*) Install DNS Server."
  # default arc
  MAJOR="1.0.0"
  MINOR="15F2"
  ARCH="amd64"

  # see if it is RPI or not?
  cat /proc/cpuinfo | grep -m 1 ARMv7 > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      ARCH="armhf"
  fi

  # download
  wget http://packages.diladele.com/dnssafety-core/$MAJOR.$MINOR/$ARCH/release/debian11/dnssafety-$MAJOR.${MINOR}_$ARCH.deb

  # install
  dpkg --install dnssafety-$MAJOR.${MINOR}_$ARCH.deb

  # relabel folder
  chown -R daemon:daemon /opt/dnssafety


  echo
  echo "(*) Starting DNS Safety daemon."
  systemctl restart dsdnsd


  echo
  echo "(*) Install Admin UI for Dns Safety."
  echo
  pkgInstall "python3-pip"
  pkgInstall "python3-dev"
  pkgInstall "libjpeg-dev"
  pkgInstall "zlib1g-dev"
  pkgInstall "libldap2-dev"
  pkgInstall "libsasl2-dev"
  pkgInstall "libssl-dev"
  pkgInstall "sudo"
  pkgInstall "dnsutils"
  pkgInstall "tmux"
  pkgInstall "libatlas-base-dev"

  # install django and all other modules
  pip3 install django==4.1
  pip3 install pytz
  pip3 install tld
  pip3 install requests
  pip3 install pandas==1.4.2
  pip3 install PyYAML
  pip3 install PyOpenSSL
  pip3 install psutil

  # there are some bugs in Ubuntu 18 and Python3 environment concerning the LDAP module,
  # so we fix them by removing obsolete ldap modules and reinstalling the correct one
  pip3 uninstall ldap
  pip3 uninstall ldap3
  pip3 uninstall python-ldap

  # ok this one is fine
  pip3 install python-ldap

  # install apache and mod_wsgi and some other useful programs
  pkgInstall "apache2"
  pkgInstall "libapache2-mod-wsgi-py3"
  pkgInstall "htop"
  pkgInstall "mc"

  # install kerberos client libraries
  export DEBIAN_FRONTEND=noninteractive 
  pkgInstall "krb5-user"


  MAJOR="1.0.0"
  MINOR="7112"
  ARCH="amd64"

  # see if it is RPI or not?
  cat /proc/cpuinfo | grep -m 1 ARMv7 > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      ARCH="armhf"
  fi

  # default os
  OSNAME="debian11"
  if [ -f "/etc/lsb-release" ]; then
      OSNAME="ubuntu20"
  fi

  # download
  wget http://packages.diladele.com/dnssafety-ui/$MAJOR.$MINOR/$ARCH/release/$OSNAME/dnssafety-ui-$MAJOR.${MINOR}_$ARCH.deb

  # install
  dpkg --install dnssafety-ui-$MAJOR.${MINOR}_$ARCH.deb

  # first relabel folder
  chown -R daemon:daemon /opt/dnssafety-ui

  # let UI of Dns Safety manage the network ONLY on amd64 based Debian 11 or Ubuntu 20, on RPI it is left as not managed
  if [ "$ARCH" != "armhf" ]; then
      sudo -u daemon python3 /opt/dnssafety-ui/var/console/utils.py --network=$OSNAME    
  fi

  # the dsdnsd daemon will listen on ports 80, 443 for a 'access blocked page'
  # so UI will be running on port 8000, it is already set so in 
  # /etc/apache2/sites-available/dnssafety-ui.conf but we also need to set
  # apache to listen on port 8000 instead of port 80 (which is taken by dsdnsd)
  sed -i 's/Listen 80/Listen 8000/g' /etc/apache2/ports.conf

  # now integrate with apache
  a2dissite 000-default
  a2ensite dnssafety-ui

  # and restart all daemons
  service apache2 restart

  # one more additional step on ubuntu
  if [ -f "/etc/lsb-release" ]; then
    # change cloud config to preserve hostname, otherwise our UI cannot set it
    sed -i 's/preserve_hostname: false/preserve_hostname: true/g' /etc/cloud/cloud.cfg
  fi

  echo
}
################################################################

################################################################
disable() {
  pkgRemove "websafety-ui"
  pkgRemove "websafety"
  rm -Rf /opt/websafety
  rm -Rf /opt/websafety-ui
  # userdel websafety
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
