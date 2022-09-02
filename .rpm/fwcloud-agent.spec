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
touch %{buildroot}/opt/fwcloud/agent/log/fwcloud-agent.log
chmod 644 %{buildroot}/opt/fwcloud/agent/log/fwcloud-agent.log

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
/usr/share/man/man1/fwcloud-agent.1
/lib/systemd/system/fwcloud-agent.service
/etc/logrotate.d/fwcloud-agent

%defattr(-,root,root,-)
/opt/fwcloud/agent/fwcloud-agent

%post
# Generate self-signed certificate.
cd /opt/fwcloud/agent/etc
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 36500 -subj '/CN=fwcloud-agent' > /dev/null 2>&1
chmod 600 key.pem cert.pem

# Generate API KEY
KEY=`openssl rand -base64 48|sed 's/[[:punct:]]/x/g'`
sed -i -E "s|API_KEY=\"([a-zA-Z0-9[:punct:]]){64}\"|API_KEY=\"$KEY\"|" /opt/fwcloud/agent/.env
chmod 600 /opt/fwcloud/agent/.env

# Enable and start FWCloud-Agent daemon.
systemctl enable fwcloud-agent
systemctl start fwcloud-agent
#systemctl status fwcloud-agent

%preun
systemctl stop fwcloud-agent
ROOT_DIR="/opt/fwcloud/agent"
DIR_LIST="${ROOT_DIR}/etc ${ROOT_DIR}/tmp ${ROOT_DIR}/data ${ROOT_DIR}/log"
for DIR in $DIR_LIST; do
  if [ -d "$DIR" ]; then
    FL=`ls $DIR`
    for F in $FL; do
      rm "${DIR}/${F}" 
    done
  fi
done

%postun
if [ -d /opt/fwcloud/agent ]; then
  if [ ! "$(ls /opt/fwcloud/agent)" ]; then
    rmdir /opt/fwcloud/agent
  fi
fi
if [ ! "$(ls /opt/fwcloud)" ]; then
  rmdir /opt/fwcloud
fi

