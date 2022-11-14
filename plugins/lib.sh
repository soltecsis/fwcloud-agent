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


################################################################
init() {
  discoverLinuxDist
  if [ -z "$DIST" ]; then
    echo "Error: Linux distribution not supported."
    echo "NOT_SUPPORTED"
    exit 1
  fi

  setGlobalVars
}
################################################################

################################################################
discoverLinuxDist() {
  which hostnamectl >/dev/null 2>&1
  if [ "$?" = "0" ]; then
    OS=`hostnamectl | grep "Operating System: " | awk -F": " '{print $2}'`
  else
    OS=`uname -a`
    if [ `echo $OS | awk '{print $1}'` = "Linux" ]; then
      if [ -f /etc/issue ]; then
        OS=`cat /etc/issue | head -n 1 | awk '{print $1" "$2" "$3}'`
      fi
    fi
  fi

  case $OS in
    'Ubuntu '*) 
      DIST="Ubuntu" 
      RELEASE=`echo "$OS" | awk -F" " '{print $2}'`
      ;;
    'Debian '*) 
      DIST="Debian"
      RELEASE=`echo "$OS" | awk -F" " '{print $4}' | awk '{print substr($0, 2, length($0) - 2)}'`
      DIST_NUMBER=`echo "$OS" | awk -F" " '{print $3}'`
      ;;
    'Red Hat Enterprise '*) DIST="RedHat";;
    'CentOS '*) DIST="CentOS";;
    'Fedora '*) DIST="Fedora";;
    'openSUSE '*) DIST="OpenSUSE";;
    'FreeBSD '*) DIST="FreeBSD";;
    'Rocky '*) DIST="Rocky";;
    *) DIST="";;
  esac
}
################################################################

################################################################
setGlobalVars() {
  case $DIST in
    'Ubuntu'|'Debian') 
      PKGM_CMD="apt-get"
      ;;

    'RedHat'|'CentOS'|'Fedora'|'Rocky') 
      PKGM_CMD="yum"
      ;;

    'OpenSUSE') 
      PKGM_CMD="zypper"
      ;;

    'FreeBSD') 
      PKGM_CMD="pkg"
      ;;
  esac
}
################################################################

################################################################
pkgInstalled() {
  # $1=pkg name.

  FOUND=""
  if [ $DIST = "Debian" -o $DIST = "Ubuntu" ]; then
    FOUND=`dpkg -s $1 2>/dev/null | grep "^Status: install ok installed"`
  elif [ $DIST = "RedHat" -o $DIST = "CentOS" -o $DIST = "Fedora" -o $DIST = "Rocky" ]; then
    rpm -q $1 >/dev/null 2>&1
    if [ "$?" = "0" ]; then
      FOUND="1"
    fi
  elif [ $DIST = "OpenSUSE" ]; then
    zypper search -i $1 >/dev/null 2>&1
    if [ "$?" = "0" ]; then
      FOUND="1"
    fi
  elif [ $DIST = "FreeBSD" ]; then
    pkg info $1 >/dev/null 2>&1
    if [ "$?" = "0" ]; then
      FOUND="1"
    fi
  fi

  if [ "$FOUND" ]; then
    return 1
  else
    return 0
  fi
}
################################################################

################################################################
pkgInstall() {
  # $1=Package name.

  echo "(*) Installing '$1' package."
  pkgInstalled "$1"
  if [ "$?" = "0" ]; then
    $PKGM_CMD install -y $1
    if [ "$?" != "0" ]; then
      echo "Error: Installing package."
      exit 1
    fi
  else
    echo "Package '$1' already installed."
  fi
  echo
}
################################################################

################################################################
pkgRemove() {
  # $1=Package name.

  echo "(*) Removing '$1' package."
  pkgInstalled "$1"
  if [ "$?" = "1" ]; then
    $PKGM_CMD remove -y $1
    if [ "$?" != "0" ]; then
      echo "Error: Removing package."
      exit 1
    fi
  else
    echo "Package '$1' not installed."
  fi
  echo
}
################################################################

################################################################
passGen() {
  PASSGEN=`cat /dev/urandom | tr -dc a-zA-Z0-9 | fold -w ${1} | head -n 1`
}
################################################################

################################################################
waitForTcpPort() {
  PORT=$1
  SERVICE="$2"
  N_TRY=$3

  echo "Waiting for ${SERVICE} servive in TCP port ${PORT} a maximum of ${N_TRY} seconds"
  while [ $N_TRY -gt 0 ]; do
    echo "$N_TRY seconds left"
    OUT=`lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep "\:${PORT}"`
    if [ "$OUT" ]; then
      echo "$SERVICE service started"
      break
    fi
    N_TRY=`expr $N_TRY - 1`
    sleep 1
  done
}
################################################################

################################################################
generateOpensslConfig() {
  cat > openssl.cnf << EOF
[ req ]
distinguished_name = req_distinguished_name
attributes = req_attributes
prompt = no
[ req_distinguished_name ]
O=SOLTECSIS - FWCloud.net
CN=${1}
[ req_attributes ]
[ cert_ext ]
subjectKeyIdentifier=hash
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
EOF
}
################################################################

################################################################
buildSelfSignedApacheCerts() {
  passGen 32
  CN="fwcloud-${1}-${PASSGEN}"
  generateOpensslConfig "$CN"

  # Private key.
  openssl genrsa -out fwcloud-${1}.key 2048

  # CSR.
  openssl req -config ./openssl.cnf -new -key fwcloud-${1}.key -nodes -out fwcloud-${1}.csr

  # Certificate.
  # WARNING: If we indicate more than 825 days for the certificate expiration date
  # we will not be able to access from Google Chrome web browser.
  openssl x509 -extfile ./openssl.cnf -extensions cert_ext -req \
    -days 825 \
    -signkey fwcloud-${1}.key -in fwcloud-${1}.csr -out fwcloud-${1}.crt
   
  rm openssl.cnf
  rm "fwcloud-${1}.csr"
}
################################################################
