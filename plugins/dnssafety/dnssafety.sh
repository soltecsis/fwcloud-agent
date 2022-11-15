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

  echo
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
  TMP_DIR="/tmp/dnssafety"
  mkdir "$TMP_DIR"
  cd "$TMP_DIR"
  wget http://packages.diladele.com/dnssafety-core/$MAJOR.$MINOR/$ARCH/release/debian11/dnssafety-$MAJOR.${MINOR}_$ARCH.deb

  # install
  dpkg --install dnssafety-$MAJOR.${MINOR}_$ARCH.deb
  if [ "$?" != "0" ]; then
    rm -rf "$TMP_DIR"
    echo "Error: Installing package."
    exit 1
  fi 

  # relabel folder
  chown -R daemon:daemon /opt/dnssafety


  echo
  echo "(*) Starting DNS Safety daemon."
  systemctl restart dsdnsd


  echo
  echo "(*) Install Admin UI for DNS Safety."
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
  #pip3 uninstall python-ldap

  # ok this one is fine
  pip3 install python-ldap

  # install apache and mod_wsgi and some other useful programs
  echo
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


  # The DNS Safety UI package has this files that are part of the Web Safety package.
  FL="/etc/logrotate.d/websafety /etc/systemd/system/wsgsbd.service /etc/systemd/system/wsicapd.service /etc/systemd/system/wssyncd.service /etc/systemd/system/wsytgd.service"
  for F in $FL; do
    if [ -f "$f" ]; then
      mv -f "$F" "${F}.FWCLOUD.TMP"
    fi
  done


  # install
  dpkg --install --force-overwrite dnssafety-ui-$MAJOR.${MINOR}_$ARCH.deb
  if [ "$?" != "0" ]; then
    rm -rf "$TMP_DIR"
    echo "Error: Installing package."
    exit 1
  fi 


  # Restore the Web Safety files.
  for F in $FL; do
    if [ -f "${F}.FWCLOUD.TMP" ]; then
      mv -f "${F}.FWCLOUD.TMP" "$F"
    fi
  done


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
  #sed -i 's/Listen 80/Listen 8000/g' /etc/apache2/ports.conf

  # now integrate with apache
  a2dissite 000-default
  a2ensite dnssafety-ui

  # Generate self signed certificates for DNS Safety UI.
  NAME="dnssafety-ui"
  buildSelfSignedCerts "${NAME}"
  mv fwcloud-${NAME}.key /opt/dnssafety-ui/etc/admin_ui.key
  mv fwcloud-${NAME}.crt /opt/dnssafety-ui/etc/admin_ui.crt

  # Disable HTTP port. Access will be allowed only by means of HTTPS.
  CFG_FILE="/etc/apache2/ports.conf"
  DSUI_PORT="8096"
  sed -i 's/Listen 80$/#Listen 80/g' "$CFG_FILE"
  # Change DNS Safety UI port and enable HTTPS.
  sed -i 's/Listen 443$/#Listen 443/g' "$CFG_FILE"
  sed -i 's/<IfModule ssl_module>/<IfModule ssl_module>\n\tListen '$DSUI_PORT'/g' "$CFG_FILE"
  sed -i 's/<IfModule mod_gnutls.c>/<IfModule mod_gnutls.c>\n\tListen '$DSUI_PORT'/g' "$CFG_FILE"
  CFG_FILE="/etc/apache2/sites-enabled/dnssafety-ui.conf"
  sed -i 's/<VirtualHost \*\:8000>/<VirtualHost \*\:'$DSUI_PORT'>\n\n    # enable HTTPS\n    SSLEngine on\n\n    # tell apache what keys to use\n    SSLCertificateFile \"\/opt\/dnssafety-ui\/etc\/admin_ui.crt\"\n    SSLCertificateKeyFile "\/opt\/dnssafety-ui\/etc\/admin_ui.key\"/g' "$CFG_FILE"

  a2enmod ssl


  # and restart all daemons
  service apache2 restart

  # one more additional step on ubuntu
  if [ -f "/etc/lsb-release" ]; then
    # change cloud config to preserve hostname, otherwise our UI cannot set it
    sed -i 's/preserve_hostname: false/preserve_hostname: true/g' /etc/cloud/cloud.cfg
  fi

  # Remove the DNS Safety temporary directory.
  rm -rf "$TMP_DIR"

  echo
  echo "(*) DNS Safety access data."
  echo "Protocol: https"
  echo "TCP port: $DSUI_PORT"
  echo "Username: root"
  echo "Password: Passw0rd"

  echo
}
################################################################

################################################################
disable() {
  pkgRemove "dnsfety-ui"
  pkgRemove "dnssafety"
  rm -Rf /opt/dnssafety
  rm -Rf /opt/dnssafety-ui
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
