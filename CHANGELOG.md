# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.6] - Unreleased
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