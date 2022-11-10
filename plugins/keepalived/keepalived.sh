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

TPL_CFG_MASTER="/etc/keepalived/keepalived.conf.FWCLOUD.MASTER"
TPL_CFG_SLAVE="/etc/keepalived/keepalived.conf.FWCLOUD.SLAVE"
TPL_CFG_LIST="$TPL_CFG_MASTER $TPL_CFG_SLAVE"
SCRIPT_FILE="/etc/keepalived/StateChange.sh.FWCLOUD"
IFL=`ip link show | grep -v "^ " | grep -v "<LOOPBACK," | grep -v "<POINTOPOINT," | awk '{print $2}' | awk -F":" '{print $1}'`
VRID=10

################################################################
cfgHeader() {
  for TPL in $TPL_CFG_LIST; do
    cat <<EOT > "$TPL"
#Global Defaults
global_defs {
  enable_script_security
  script_user root
}

#Sync Groups
vrrp_sync_group G1 {   # must be before vrrp_instance declaration
  group {
EOT

    for IF in $IFL; do
      echo "    VI_${IF}" >> "$TPL"
    done

    cat <<EOT >> "$TPL"
  }
}
#---------

#Virtual Instances
EOT
  done
}
################################################################

################################################################
cfgVirtualInstance() {
  IF="$1"
  IP=`ip addr show $IF | grep inet | head -n 1 | awk '{print $2}' | awk -F"/" '{print $1}'`
  B1=`echo $IP | awk -F"." '{print $1}'`
  B2=`echo $IP | awk -F"." '{print $2}'`
  B3=`echo $IP | awk -F"." '{print $3}'`
  passGen 8

  cat <<EOT >> "$TPL_CFG_MASTER"
vrrp_instance VI_${IF} {
  interface ${IF}		#Interface IP keepalived listens on
  unicast_src_ip ${IP}	#Source IP used for unicast communication
  unicast_peer {
    ${B1}.${B2}.${B3}.2		#Unicast peer
  }
  state BACKUP
  virtual_router_id ${VRID}
  priority 99
  advert_int 5
  authentication {
    auth_type AH
    auth_pass ${PASSGEN}
  }
  virtual_ipaddress {
    ${B1}.${B2}.${B3}.254 label ${IF}:254 dev ${IF}
  }
  notify "/etc/keepalived/StateChange.sh"
  notify_stop "/etc/keepalived/StateChange.sh INSTANCE VI_${IF} STOP"
}

EOT

  cat <<EOT >> "$TPL_CFG_SLAVE"
vrrp_instance VI_${IF} {
  interface ${IF}             #Interface IP keepalived listens on
  unicast_src_ip ${IP}   #Source IP used for unicast communication
  unicast_peer {
    ${B1}.${B2}.${B3}.1             #Unicast peer
  }
  state BACKUP
  virtual_router_id ${VRID}
  priority 9
  advert_int 5
  authentication {
    auth_type AH
    auth_pass ${PASSGEN}
  }
  virtual_ipaddress {
    ${B1}.${B2}.${B3}.254 label ${IF}:254 dev ${IF}
  }
  notify "/etc/keepalived/StateChange.sh"
  notify_stop "/etc/keepalived/StateChange.sh INSTANCE VI_${IF} STOP"
}

EOT

  VRID=`expr $VRID + 1`
}
################################################################

################################################################
cfgFooter() {
  for TPL in $TPL_CFG_LIST; do
    cat <<EOT >> "$TPL"
#EoF!
EOT
  done
}
################################################################

################################################################
scriptHeader() {
  cat <<EOT > "$SCRIPT_FILE"
#!/bin/bash
#-------
#Take actions when Sync Group state changes
#\$1 == INSTANCE or GROUP depending on where Keekalived invoked the script from
#\$2 == Sync Group or instance name
#\$3 == end state: BACKUP, FAULT, MASTER.
#-------

#VARIABLES
#---
endState=\$3
NAME=\$2
TYPE=\$1
logFile=/var/log/keepalived/keepalived.log
dateTime=\$(date +"%Y%m%d_%H:%M:%S")

#MAIN
#---
echo "\${dateTime} - \${TYPE} \${NAME} has changed to \${endState} state (\$0 \$1 \$2 \$3)" >> "\${logFile}"
case \$NAME in
EOT
}
################################################################

################################################################
scriptSection() {
  IF="$1"
  cat <<EOT >> "$SCRIPT_FILE"
  
  #Virtual Interface VI_${IF}
  "VI_${IF}")
    case \$endState in
      "BACKUP") #
        ;;
      "FAULT")  #
        ;;
      "MASTER") #
        ;;
      "STOP")   #
        ;;
      *) echo "Unknown state \${endState} for VRRP \${TYPE} \${NAME}" >> "\${logFile}"
        ;;
    esac
  ;;
EOT
}
################################################################

################################################################
scriptFooter() {
  cat <<EOT >> "$SCRIPT_FILE"

  #Undefined Virtual Interface
  *) echo "\$dateTime - WARNING: undefined virtual interface (\${NAME})" >> "\${logFile}"
  ;;

esac
#EoF!
EOT
}
################################################################

################################################################
enable() {
  pkgInstall "keepalived"

  echo "(*) Generating config and script templates."
  echo "Header"
  cfgHeader
  scriptHeader

  echo "Content"
  for IF in $IFL; do
    echo "  Network interface: $IF"
    cfgVirtualInstance "$IF"
    scriptSection "$IF"
  done

  echo "Footer"
  cfgFooter
  scriptFooter

  echo
  echo "(*) Configuration and script templates generated here."
  echo "$TPL_CFG_MASTER"
  echo "$TPL_CFG_SLAVE"
  echo "$SCRIPT_FILE"

  echo
}
################################################################

################################################################
disable() {
  pkgRemove "keepalived"
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
