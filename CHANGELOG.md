# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.0.0] - 2021-11-10
### Added
- Worker thread for collect OpenVPN server status data dumped in the status file.
- API call for get OpenVPN server status data collected by the worker thread.
- API call for get OpenVPN server status in real time.
- API call for upload OpenVPN config files.
- API call for remove OpenVPN config files.
- API call for retrieve the sha256 hash of the OpenVPN CCD files. 
- API call for upload FWCloud policy script and load firewall policy.
- API call for retrieve network interfaces information.
- API call for get iptables-save output.
- Ping API call.