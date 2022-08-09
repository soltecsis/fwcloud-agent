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
  if [ -z "$DIST "]; then
    echo "ERROR: Linux distribution not supported."
    echo "NOT_SUPORTED"
    exit 1
  fi

  setGlobalVars
}
################################################################

################################################################
discoverLinuxDist() {
  which hostnamectl >/dev/null 2>&1
  if [ "$?" = "0" ]; then
    OS=`hostnamectl | grep "^  Operating System: " | awk -F": " '{print $2}'`
  else
    OS=`uname -a`
    if [ `echo $OS | awk '{print $1}'` = "Linux" ]; then
      if [ -f /etc/issue ]; then
        OS=`cat /etc/issue | head -n 1 | awk '{print $1" "$2" "$3}'`
      fi
    fi
  fi
  case $OS in
    'Ubuntu '*) DIST="Ubuntu";;
    'Debian '*) DIST="Debian";;
    'Red Hat Enterprise '*) DIST="RedHat";;
    'CentOS '*) DIST="CentOS";;
    'Fedora '*) DIST="Fedora";;
    'openSUSE '*) DIST="OpenSUSE";;
    'FreeBSD '*) DIST="FreeBSD";;
    *) DIST="";;
  esac
}
################################################################

################################################################
setGlobalVars() {
  case $DIST in
    'Ubuntu'|'Debian') 
      PKGM_CMD="apt"
      ;;

    'RedHat'|'CentOS'|'Fedora') 
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
  elif [ $DIST = "RedHat" -o $DIST = "CentOS" -o $DIST = "Fedora" ]; then
    rpm -q $1 >/dev/null 2>&1
    if [ "$?" = 0 ]; then
      FOUND="1"
    fi
  elif [ $DIST = "OpenSUSE" ]; then
    zypper search -i $1 >/dev/null 2>&1
    if [ "$?" = 0 ]; then
      FOUND="1"
    fi
  elif [ $DIST = "FreeBSD" ]; then
    pkg info $1 >/dev/null 2>&1
    if [ "$?" = 0 ]; then
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
  # $1=Display name.
  # $2=pkg name.

  pkgInstalled "$2"
  if [ "$?" = "0" ]; then
    $PKGM_CMD install -y $2
  else
    echo "Package '$2' already installed."
  fi
}
################################################################

################################################################
pkgRemove() {
  # $1=Display name.
  # $2=pkg name.

  pkgInstalled "$2"
  if [ "$?" = "1" ]; then
    $PKGM_CMD remove -y $2
  else
    echo "Package '$2' not installed."
  fi
}
################################################################

