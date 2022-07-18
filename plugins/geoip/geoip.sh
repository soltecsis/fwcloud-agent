#!/bin/bash

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