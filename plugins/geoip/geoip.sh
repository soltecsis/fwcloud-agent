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

. ../lib.sh
init

DST_DIR="/usr/share/xt_geoip"

################################################################
enable() {
  echo "Installing packages: xtables-addons-common libtext-csv-xs-perl"
  pkgInstall "xtables-addons-common" "xtables-addons-common"
  pkgInstall "libtext-csv-xs-perl" "libtext-csv-xs-perl"

  echo "Creating destination directory: ${DST_DIR}"
  mkdir "${DST_DIR}"

  echo "Downloading the latest version of the GeoIP database."
  cd /tmp
  /usr/lib/xtables-addons/xt_geoip_dl

  echo "Generating binary files for the xt_geoip module."
  chmod 755 /usr/lib/xtables-addons/xt_geoip_build
  /usr/lib/xtables-addons/xt_geoip_build -D "${DST_DIR}"
  rm -f dbip-country-lite.csv

  echo "Creating cron task for daily update the GeoIP database."
}
################################################################

################################################################
disable() {
  echo "Removing cron task for GeoIP database update."

  echo "Removing packages: xtables-addons-common libtext-csv-xs-perl"
  pkgRemove "xtables-addons-common" "xtables-addons-common"
  pkgRemove "libtext-csv-xs-perl" "libtext-csv-xs-perl"

  echo "Removing destination directory: ${DST_DIR}"
  rm -rf "${DST_DIR}"
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