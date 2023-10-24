/*
    Copyright 2022 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
    https://soltecsis.com
    info@soltecsis.com


    This file is part of FWCloud (https://fwcloud.net).

    FWCloud is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FWCloud is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FWCloud.  If not, see <https://www.gnu.org/licenses/>.
*/

use regex::Regex;

lazy_static! {
  pub static ref IPV4: Regex = Regex::new("^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$").unwrap();
  pub static ref IPV4_LIST: Regex = Regex::new("^(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3})( ?))*$").unwrap();

  pub static ref IPV6: Regex = Regex::new("(^\\d{20}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff(:[a-fA-F0-9]{1,4}){2}$)|(^([a-fA-F0-9]{1,4}) (:[a-fA-F0-9]{1,4}){7}$)|(^:(:[a-fA-F0-9]{1,4}(::)?){1,6}$)|(^((::)?[a-fA-F0-9]{1,4}:){1,6}:$)|(^::$)").unwrap();
  pub static ref IPV6_LIST: Regex = Regex::new("(((^\\d{20}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff(:[a-fA-F0-9]{1,4}){2}$)|(^([a-fA-F0-9]{1,4}) (:[a-fA-F0-9]{1,4}){7}$)|(^:(:[a-fA-F0-9]{1,4}(::)?){1,6}$)|(^((::)?[a-fA-F0-9]{1,4}:){1,6}:$)))*$").unwrap();

  pub static ref ALPHA_NUM: Regex = Regex::new("^[a-zA-Z0-9]*$").unwrap();
  pub static ref ALPHA_NUM_2: Regex = Regex::new("^[a-zA-Z0-9\\-_]*$").unwrap();

  pub static ref FILE_PERMISSIONS: Regex = Regex::new("^[0-7]{3}$").unwrap();

  pub static ref ABSOLUTE_PATH: Regex = Regex::new("^/{1}(((/{1}\\.{1})?[a-zA-Z0-9 -_]+/?)+(\\.{1}[a-zA-Z0-9]{2,4})?)$").unwrap();
  pub static ref ABSOLUTE_PATH_LIST: Regex = Regex::new("^((/{1}(((/{1}\\.{1})?[a-zA-Z0-9 -_]+/?)+(\\.{1}[a-zA-Z0-9]{2,4})?))(,?))*$").unwrap();

  pub static ref PLUGINS_NAMES: Regex = Regex::new("^(test|openvpn|geoip|crowdsec|ntopng|suricata|keepalived|zeek|elasticsearch|filebeat|websafety|dnssafety|kibana|logstash|isc-bind9|isc-dhcp|haproxy)$").unwrap();
  pub static ref PLUGINS_ACTIONS: Regex = Regex::new("^(enable|disable)$").unwrap();

  pub static ref SYSTEMCTL_COMMANDS: Regex = Regex::new("^(status|start|stop|restart|reload|enable|disable)$").unwrap();
  pub static ref SYSTEMCTL_SERVICES: Regex = Regex::new("^(openvpn|openvpn@[a-zA-Z0-9\\-_]+|isc-dhcp-server|keepalived|haproxy)$").unwrap();
}
