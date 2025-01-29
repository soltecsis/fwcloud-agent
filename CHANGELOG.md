# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-01-29
## Added
- WireGuard plugin.
- IPSec plugin.

## Fixed
- Several CI fixes and actions updates.
- Changes needed for upgrade to the latest `validator` crate.
- Updated Rust packages to the latest version.


## [2.0.1] - 2024-04-21
## Added
- Crates update to the latest supported versions.
- Return all output data for `systemctl` commands, even with the exit status of such command is not 0.


## [2.0.0] - 2024-01-28
## Added
- API call for install configuration files for the DHCP, Keepalived and HAProxy services.
- New plugin script for the `HAProxy`` service.
- API call for gather information about the host in which the FWCloud agent is running. With this API call we can obtain information like FWCloud-Agent version, host name, OS, etc. 
- API call for services management by means of `systemctl`.
- Allow only a limited set of services to be managed by the `systemctl` API call.
- Software tests for check the new `systemctl` API call.

## Fixed
- Changes needed for upgrade to the latest `sysinfo` crate.
- Updated Rust packages to the latest version.
- All problems reported by the `cargo audit` command.


## [1.4.0] - 2023-08-30
### Fixed
- Since `OpenVPN 2.5` the datetime string format used in the `openvpn-status.log` file has changed. Before to this version the format was like this `Fri Jul 21 14:35:56 2023`, and the new format is like this `2023-07-21 15:02:00`. We have modified the code for support both formats.
- Updated Rust packages to the latest version.
- Replaced the unmaintained `dotenv` crate by the well well-maintained fork called `dotenvy`.
- All problems reported by the `cargo audit` command.
- Reenable `cargo tarpaulin` in GitHub Actions.


## [1.3.1] - 2023-03-23 
### Added
- PackageCloud repositories for DEB and RPM any packages.
- ISC DHCP plugin.
- ISC Bind9 plugin.
- Control script exit status in `run_cmd` and `run_cmd_ws` functions. It the exit status is not 0 then return an Internal server error as response to the API call.


## [1.2.3] - 2023-02-01
### Fixed
- Syntax error in packages dependency definition for `deb` packages.


## [1.2.2] - 2023-01-31
### Added
- IPTables package dependency for both `deb` and `rpm` packages.

### Changed
- GitHub actions `rpm` package generation task for use `--target=x86_64-unknown-linux-musl`. This way the FWCloud-Agent `rpm` package will be compatible with most Linux rpm based distributions.

### Fixed
- Updated several crates with its latest versions.


## [1.2.1] - 2022-11-16
### Fixed
- Bug in RPM package generation.


## [1.2.0] - 2022-11-16
### Added
- Keepalived plugin.
- Suricata plugin.
- Zeek plugin.
- Elasticsearch plugin.
- Kibana plugin.
- Logstash plugin.
- Filebeat plugin.
- Web Safety Proxy plugin.
- DNS Safety plugin.
- CrowdSec plugin.
- NtopNG plugin.


## [1.1.8] - 2022-09-19
### Added
- Support for Rocky Linux distribution.
- Improved script for GeoIP plugin.

### Fixed
- Incorrect UTF-8 management in output of executed scripts.


## [1.1.7] - 2022-09-14
### Added
- More Linux distributions support in packagecloud.io.
- Allow the use of websocket realtime output in the API call for upload and install firewall policy.
- Debug logs for all mutex locking and release operations.
- Conflict packages list for `.rpm` package.

### Fixed
- Bug in plugins lib `discoverLinuxDist` function.
- Websockets map was locked during all the plugins and firewall policy load scripts run time. Now lock only for get the websocket data structure and release it immediately.


## [1.1.6] - 2022-09-07
### Added
- Display FWCloud-Agent version on startup.
   
### Fixed
- For the `.rpm` package, in the update procedure, preserve the files that we want to keep after the update has been completed.
- Several bugs in `.rpm` package generation.


## [1.1.5] - 2022-09-07
### Fixed
- For the `.deb` package, in the update procedure, preserve the files that we want to keep after the update has been completed.


## [1.1.4] - 2022-09-06
### Fixed
- Bug in `.dep` package generation. Use target `x86_64-unknown-linux-musl` instead of `x86_64-unknown-linux-gnu` for avoid `glibc` dependency.


## [1.1.3] - 2022-09-05
### Fixed
- Exclude `.tmp0-stripped` file in `.deb` package upload.


## [1.1.2] - 2022-09-05
### Fixed
- Fix a bug in package dependencies definition.


## [1.1.1] - 2022-09-05
### Added
- Define a conflict with the `firewalld` package for `fwcloud-agent` `.deb` and `.rpm` packages.
  
### Fixed
- Use `apt-get` instead of `apt` in order to avoid warning message in plugins activation/deactivation scripts.


## [1.1.0] - 2022-09-02
### Added
- API call for get information about the host in which FWCloud-Agent is running.
- API call for create a WebSocket communication channel.
- Plugins ecosystem support.
- Plugin for OpenVPN.
- Plugin for GeoIP.
- Improve CI pipeline.
- New config option (ENABLE_API_KEY) for enable/disable API access by means of API Key. By default it will be enabled.
- Integration tests for all API calls.
- Debian package dependency for sudo.

### Changed
- Updated all crates, including the Actix-Web ones.
- Removed unnecessary crates.
- Program structure for simplify integration tests creation.


## [1.0.0] - 2021-12-02
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