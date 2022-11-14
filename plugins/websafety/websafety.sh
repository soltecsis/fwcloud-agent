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
  echo "Error: Only Ubuntu 20 and Debian 11 are supported for this plugin."
  echo "NOT_SUPPORTED"
  exit 1
}
################################################################

################################################################
enable() {
  MAJ=`echo $RELEASE | cut -c1-2`
  if [ $DIST != "Ubuntu" -a $DIST != "Debian" ]; then
    notSupported
  elif [ $DIST = "Ubuntu" -a $MAJ != "20" ]; then
    notSupported
  elif [ $DIST = "Debian" -a $RELEASE != "bullseye" ]; then
    notSupported
  fi

  # https://docs.diladele.com/administrator_guide_stable/install/ubuntu20/index.html
  # https://docs.diladele.com/administrator_guide_stable/install/debian11/index.html
  
  echo "(*) Cloning Web Safety Proxy GitHUB repository."
  cd /tmp
  rm -rf websafety
  git clone https://github.com/diladele/websafety.git
  if [ "$DIST" = "Ubuntu" ]; then
    cd websafety/core.ubuntu20
  else # Debian
    cd websafety/core.debian11
  fi

  if [ "$DIST" = "Ubuntu" ]; then
    echo
    echo "(*) Enabling the Universe repository."
    # some packages are in universe, so enable it
    add-apt-repository universe

    echo
    echo "(*) Adding the Diladele repository."
    echo -n "Importing Diladele GPG key ... "
    # add diladele apt key
    wget -qO - https://packages.diladele.com/diladele_pub.asc | APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE="1" apt-key add -
    # add new repo
    echo "deb https://squid55.diladele.com/ubuntu/ focal main" > /etc/apt/sources.list.d/squid55.diladele.com.list
    apt-get update

    echo
    pkgInstall "squid-common" 
    pkgInstall "squid-openssl" 
    pkgInstall "squidclient" 
    pkgInstall "libecap3" 
    pkgInstall "libecap3-dev" 
  else # Debian
    echo
    pkgInstall "squid-openssl" 
    pkgInstall "squidclient" 
    pkgInstall "sudo" 
  fi


  echo "(*) Squid setup."
  # change the number of default file descriptors
  OVERRIDE_DIR=/etc/systemd/system/squid.service.d
  OVERRIDE_CNF=$OVERRIDE_DIR/override.conf
  mkdir -p $OVERRIDE_DIR
  # generate the override file
  if [ -f "$OVERRIDE_CNF" ]; then
    rm $OVERRIDE_CNF
  fi
  echo "[Service]"         >> $OVERRIDE_CNF
  echo "LimitNOFILE=65535" >> $OVERRIDE_CNF
  # and reload the systemd
  systemctl daemon-reload

  # install clamav
  echo
  pkgInstall "clamav"
  pkgInstall "clamav-daemon"
  pkgInstall "libclamav-dev"
  pkgInstall "g++"
  pkgInstall "make"
  pkgInstall "patch"
  pkgInstall "libecap3"
  pkgInstall "libecap3-dev"
  pkgInstall "pkg-config"

  echo "(*) Install ClamAV eCAP Adapter."
  # download the sources
  wget https://www.e-cap.org/archive/ecap_clamav_adapter-2.0.0.tar.gz

  # unpack
  tar -xvzf ecap_clamav_adapter-2.0.0.tar.gz

  # patch the CL_SCAN_STDOPT error
  patch ecap_clamav_adapter-2.0.0/src/ClamAv.cc < ClamAv.cc.patch

  # change into working dir
  cd ecap_clamav_adapter-2.0.0

  # build
  ./configure && make && make install

  # revert back
  cd ..


  echo
  echo "(*) Install Web Safety Core."
  # install web safety core daemons
  MAJOR="8.2.0"
  MINOR="0CD3"
  ARCH="amd64"

  # download
  wget https://packages.diladele.com/websafety-core/$MAJOR.$MINOR/$ARCH/release/ubuntu20/websafety-$MAJOR.${MINOR}_$ARCH.deb

  # install
  dpkg --install websafety-$MAJOR.${MINOR}_$ARCH.deb

  # for the authenticated portal to work we need to show our own deny info for 511 requests
  # due to the bug in squid it thinks the path start in templates not on /
  mkdir -p /usr/share/squid/errors/templates/opt/websafety/etc/squid

  # so we make a link to trick it
  ln -s /opt/websafety/etc/squid/portal.html /usr/share/squid/errors/templates/opt/websafety/etc/squid/portal.html

  # web safety runs using the same user as squid
  chown -R proxy:proxy /opt/websafety

  # replace the squid config
  if [ ! -f /etc/squid/squid.conf.default ]; then
      cp -f /etc/squid/squid.conf /etc/squid/squid.conf.default
  fi
  cp -f squid.conf /etc/squid/squid.conf

  # re-initialize storage for mimicked ssl certificates
  SSL_DB=/var/spool/squid_ssldb
  if [ -d $SSL_DB ]; then
      rm -Rf $SSL_DB
  fi
  /usr/lib/squid/security_file_certgen -c -s $SSL_DB -M 4MB
  if [ $? -ne 0 ]; then
      echo "Error $? while initializing SSL certificate storage, exiting..."
      exit 1
  fi

  # relabel folder
  chown -R proxy:proxy $SSL_DB

  # and restart all daemons
  systemctl start wsicapd && service squid restart


  echo
  echo "(*) Install Admin UI for Web Safety."
  echo
  # install pip3 and other python modules, ldap/sasl (we need it for python ldap module)
  pkgInstall "python3-pip"
  pkgInstall "python3-dev"
  pkgInstall "libjpeg-dev"
  pkgInstall "zlib1g-dev"
  pkgInstall "libldap2-dev"
  pkgInstall "libsasl2-dev"
  pkgInstall "libssl-dev"
  pkgInstall "net-tools"

  # on RPI install libatlas for numpy
  cat /proc/cpuinfo | grep -m 1 ARMv7 > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      apt-get install libatlas-base-dev
  fi

  # install django and all other modules
  pip3 install django==4.1
  pip3 install pytz
  pip3 install tld
  pip3 install requests
  pip3 install pandas==1.4.2
  pip3 install PyYAML
  pip3 install PyOpenSSL
  pip3 install psutil
  pip3 install jinja2
  pip3 install msal

  # there are some bugs in Ubuntu 20 and Python3 environment concerning the LDAP module,
  # so we fix them by removing obsolete ldap modules and reinstalling the correct one
  pip3 uninstall ldap
  pip3 uninstall ldap3
  pip3 uninstall python-ldap

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

  # default arch and version
  MAJOR="8.2.0"
  MINOR="6328"
  ARCH="amd64"

  # default os
  OSNAME="debian11"
  if [ -f "/etc/lsb-release" ]; then
      OSNAME="ubuntu20"
  fi

  # download
  wget https://packages.diladele.com/websafety-ui/$MAJOR.$MINOR/$ARCH/release/$OSNAME/websafety-ui-$MAJOR.${MINOR}_$ARCH.deb

  # install
  dpkg --install websafety-ui-$MAJOR.${MINOR}_$ARCH.deb

  # sync ui and actual files in disk (note UI does not manage network by default)
  sudo -u proxy python3 /opt/websafety-ui/var/console/generate.py --core
  sudo -u websafety python3 /opt/websafety-ui/var/console/generate.py --ui

  # relabel folder
  chown -R websafety:websafety /opt/websafety-ui

  # Admin UI now runs using HTTPS so to integrate with apache, we need to enable the HTTPS
  a2enmod ssl

  # disable the default site and enable web safety
  a2dissite 000-default
  a2ensite websafety


  # Generate self signed certificates for Web Safety UI.
  NAME="websafety-ui"
  buildSelfSignedCerts "${NAME}"
  mv fwcloud-${NAME}.key /opt/websafety-ui/etc/admin_ui.key
  mv fwcloud-${NAME}.crt /opt/websafety-ui/etc/admin_ui.crt

  # Disable HTTP port. Access will be allowed only by means of HTTPS.
  CFG_FILE="/etc/apache2/ports.conf"
  WSUI_PORT="8095"
  sed -i 's/Listen 80$/#Listen 80/g' "$CFG_FILE"
  # Change Web Safety UI port.
  sed -i 's/Listen 443$/#Listen 443/g' "$CFG_FILE"
  sed -i 's/<IfModule ssl_module>/<IfModule ssl_module>\n\tListen '$WSUI_PORT'/g' "$CFG_FILE"
  sed -i 's/<IfModule mod_gnutls.c>/<IfModule mod_gnutls.c>\n\tListen '$WSUI_PORT'/g' "$CFG_FILE"
  CFG_FILE="/etc/apache2/sites-enabled/websafety.conf"
  sed -i 's/<VirtualHost \*\:443>/<VirtualHost \*\:'$WSUI_PORT'>/g' "$CFG_FILE"


  # finally restart all daemons
  service apache2 restart

  # Remove GitHub cloned repository.
  rm -rf /tmp/websafety


  echo
  echo "(*) Web Safety Proxy access data."
  echo "Protocol: https"
  echo "TCP port: $WSUI_PORT"
  echo "Username: admin"
  echo "Password: Passw0rd"

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
