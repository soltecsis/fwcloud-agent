#!/bin/bash

. ../lib.sh
init

################################################################
enable() {
  echo "Installing OpenVPN package."
  pkgInstall "OpenVPN" "openvpn"
}
################################################################

################################################################
disable() {
  echo "Removing OpenVPN package."
  pkgRemove "OpenVPN" "openvpn"
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
