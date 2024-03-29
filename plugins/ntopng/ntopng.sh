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
  if [ $DIST = "Ubuntu" ]; then
    pkgInstall "software-properties-common"
    pkgInstall "wget"
    
    echo "(*) Adding Universe repository."
    add-apt-repository universe

    echo
    echo "(*) Downloading Ntop package."
    wget https://packages.ntop.org/apt-stable/`echo $RELEASE | cut -c1-5`/all/apt-ntop-stable.deb
    if [ "$?" != "0" ]; then
      echo "Error: Downloading Ntop package"
      exit 1
    fi

    echo "(*) Installing Ntop package."
    apt-get install ./apt-ntop-stable.deb

    echo
    echo "(*) Updating packages lists."
    apt-get clean all
    apt-get update
    
    echo
    pkgInstall "pfring-dkms"
    pkgInstall "nprobe"
    pkgInstall "ntopng"
    pkgInstall "n2disk"
    pkgInstall "cento"
    pkgInstall "pfring-drivers-zc-dkms"
  elif [ $DIST = "Debian" ]; then
    echo "(*) Downloading Ntop package."
    wget https://packages.ntop.org/apt-stable/$RELEASE/all/apt-ntop-stable.deb
    if [ "$?" != "0" ]; then
      echo "Error: Downloading Ntop package"
      exit 1
    fi

    echo
    echo "(*) Installing Ntop package."
    apt-get install ./apt-ntop-stable.deb

    echo
    echo "(*) Updating packages lists."
    apt-get clean all
    apt-get update
    
    echo
    pkgInstall "pfring-dkms"
    pkgInstall "nprobe"
    pkgInstall "ntopng"
    pkgInstall "n2disk"
    pkgInstall "cento"
    pkgInstall "pfring-drivers-zc-dkms"
  elif [ $DIST = "CentOS" -o $DIST = "Rocky" ]; then
    echo "(*) Adding the NtopNG repository."
    curl https://packages.ntop.org/centos-stable/ntop.repo > /etc/yum.repos.d/ntop.repo

    echo
    echo "(*) Updating packages lists."
    yum clean all
    yum update

    echo
    pkgInstall "epel-release"
    pkgInstall "pfring-dkms"
    pkgInstall "nprobe"
    pkgInstall "ntopng"
    pkgInstall "n2disk"
    pkgInstall "cento"
    pkgInstall "pfring-drivers-zc-dkms"

    echo "(*) Installing NtopNG packages."
  else
    echo "Error: Linux distribution not supported."
    echo "NOT_SUPPORTED"
    exit 1
  fi
}
################################################################

################################################################
disable() {
  pkgRemove "pfring-drivers-zc-dkms"
  pkgRemove "cento"
  pkgRemove "n2disk"
  pkgRemove "nprobe"
  pkgRemove "ntopng"
  pkgRemove "pfring-dkms"
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
