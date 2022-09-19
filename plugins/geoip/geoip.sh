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

DST_DIR="/usr/share/xt_geoip"
CRON_FILE="/etc/cron.daily/xt_geoip_dl"

################################################################
where_is() {
  if [ "$1" = "xt_geoip_dl" ]; then
    XT_GEOIP_DL=""
    DIR_L="lib libexec"
    for DIR in $DIR_L; do
      if [ -f "/usr/${DIR}/xtables-addons/xt_geoip_dl" ]; then
        XT_GEOIP_DL="/usr/${DIR}/xtables-addons/xt_geoip_dl"
        break
      fi
    done
    if [ -z "$XT_GEOIP_DL" ]; then
      echo "Error: xt_geoip_dl file not found."
      exit 1
    fi
  else
    XT_GEOIP_BUILD=""
    DIR_L="lib libexec"
    for DIR in $DIR_L; do
      if [ -f "/usr/${DIR}/xtables-addons/xt_geoip_build" ]; then
        XT_GEOIP_BUILD="/usr/${DIR}/xtables-addons/xt_geoip_build"
        break
      fi
    done
    if [ -z "$XT_GEOIP_BUILD" ]; then
      echo "Error: xt_geoip_build file not found."
      exit 1
    fi
  fi
}
################################################################

################################################################
enable() {
  pkgInstall "xtables-addons-common"
  pkgInstall "libtext-csv-xs-perl"

  echo "(*) Creating destination directory: ${DST_DIR}"
  if [ ! -d "${DST_DIR}" ]; then
    mkdir "${DST_DIR}"
  else
    echo "Already exists."
  fi
  echo

  echo "(*) Downloading the latest version of the GeoIP database."
  cd /tmp
  where_is "xt_geoip_dl"
  $XT_GEOIP_DL
  if [ "$?" != "0" ]; then
    echo "Error: Running xt_geoip_dl"
    exit 1
  fi
  echo

  echo "(*) Generating binary files for the xt_geoip module."
  where_is "xt_geoip_build"
  chmod 755 "${XT_GEOIP_BUILD}"
  $XT_GEOIP_BUILD -D "${DST_DIR}"
  if [ "$?" != "0" ]; then
    echo "Error: Running xt_geoip_build"
    exit 1
  fi
  rm -f dbip-country-lite.csv
  echo

  echo "(*) Creating cron task for daily update the GeoIP database."
  echo "#"'!'"/bin/sh\n\ncd /tmp\n${XT_GEOIP_DL}\n$XT_GEOIP_BUILD -D \"${DST_DIR}\"\nrm -f dbip-country-lite.csv\n\nexit 0" > "${CRON_FILE}"
  chmod 755 "${CRON_FILE}"
  echo
}
################################################################

################################################################
disable() {
  echo "(*) Removing cron task for GeoIP database update."
  rm -f "${CRON_FILE}"
  echo

  echo "(*) Removing destination directory: ${DST_DIR}"
  rm -rf "${DST_DIR}"
  echo

  pkgRemove "xtables-addons-common"
  pkgRemove "libtext-csv-xs-perl"
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