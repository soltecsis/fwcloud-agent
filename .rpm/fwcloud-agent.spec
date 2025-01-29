%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: fwcloud-agent
Summary: FWCloud Agent for firewalls management
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: GNU AFFERO GENERAL PUBLIC LICENSE
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://fwcloud.net
Vendor: SOLTECSIS, SL
Packager: Carles Munyoz <cmunyoz@soltecsis.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
FWCloud Agent daemon for simplify and improve
firewalls management from a FWCloud console.

%prep
%setup -q 

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}
mkdir %{buildroot}/opt/fwcloud/agent/etc
mkdir %{buildroot}/opt/fwcloud/agent/data
mkdir %{buildroot}/opt/fwcloud/agent/tmp
mkdir %{buildroot}/opt/fwcloud/agent/log
chmod -R 700 %{buildroot}/opt/fwcloud/agent

%clean
rm -rf %{buildroot}

%files
/opt/fwcloud/agent/fwcloud-agent
/opt/fwcloud/agent/.env
/opt/fwcloud/agent/etc/
/opt/fwcloud/agent/data/
/opt/fwcloud/agent/tmp/
/opt/fwcloud/agent/log/
/opt/fwcloud/agent/plugins/lib.sh
/opt/fwcloud/agent/plugins/geoip/geoip.sh
/opt/fwcloud/agent/plugins/openvpn/openvpn.sh
/opt/fwcloud/agent/plugins/wireguard/wireguard.sh
/opt/fwcloud/agent/plugins/ipsec/ipsec.sh
/opt/fwcloud/agent/plugins/crowdsec/crowdsec.sh
/opt/fwcloud/agent/plugins/ntopng/ntopng.sh
/opt/fwcloud/agent/plugins/suricata/suricata.sh
/opt/fwcloud/agent/plugins/zeek/zeek.sh
/opt/fwcloud/agent/plugins/zeek/zeek.service
/opt/fwcloud/agent/plugins/elasticsearch/elasticsearch.sh
/opt/fwcloud/agent/plugins/kibana/kibana.sh
/opt/fwcloud/agent/plugins/logstash/logstash.sh
/opt/fwcloud/agent/plugins/filebeat/filebeat.sh
/opt/fwcloud/agent/plugins/keepalived/keepalived.sh
/opt/fwcloud/agent/plugins/websafety/websafety.sh
/opt/fwcloud/agent/plugins/dnssafety/dnssafety.sh
/opt/fwcloud/agent/plugins/isc-bind9/isc-bind9.sh
/opt/fwcloud/agent/plugins/isc-dhcp/isc-dhcp.sh
/opt/fwcloud/agent/plugins/haproxy/haproxy.sh
/usr/share/man/man1/fwcloud-agent.1
/lib/systemd/system/fwcloud-agent.service
/etc/logrotate.d/fwcloud-agent

%defattr(-,root,root,-)
/opt/fwcloud/agent/fwcloud-agent

%pre
ROOT_DIR="/opt/fwcloud/agent"
if [ $1 -gt 1 ]; then
  # Preserve the .env configuration file.
  mv -f "${ROOT_DIR}/.env" "${ROOT_DIR}/.env.upgrade"
fi

%post
ROOT_DIR="/opt/fwcloud/agent"
# Generate self-signed certificate.
if [ ! -f "${ROOT_DIR}/etc/key.pem" -o ! -f "${ROOT_DIR}/etc/cert.pem" ]; then
  cd "${ROOT_DIR}/etc"
  openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 36500 -subj '/CN=fwcloud-agent' > /dev/null 2>&1
  chmod 600 key.pem cert.pem
fi

# Generate API KEY
if [ -f "${ROOT_DIR}/.env.upgrade" ]; then
  mv -f "${ROOT_DIR}/.env.upgrade" "${ROOT_DIR}/.env"
else
  KEY=`openssl rand -base64 48|sed 's/[[:punct:]]/x/g'`
  sed -i -E "s|API_KEY=\"([a-zA-Z0-9[:punct:]]){64}\"|API_KEY=\"$KEY\"|" "${ROOT_DIR}/.env"
fi

# Enable and start FWCloud-Agent daemon.
systemctl enable fwcloud-agent
if [ $1 -gt 1 ] ; then
  systemctl restart fwcloud-agent
else
  systemctl start fwcloud-agent
fi
#systemctl status fwcloud-agent

%preun
if [ $1 -eq 0 ]; then
  systemctl stop fwcloud-agent
fi

%postun
if [ $1 -eq 0 ]; then
  rm -rf /opt/fwcloud
fi
