use super::*;
use std::fs::File;
use std::path::Path;
use uuid::Uuid;

fn tmp_dir() -> String {
    format!("/tmp/fwcloud-agent-openvpn-dir-{}", Uuid::new_v4())
}

fn dir_config(dir: String, group: &str) -> OpenVPNDirConfig {
    OpenVPNDirConfig {
        dir,
        owner: String::from("root"),
        group: String::from(group),
        mode: String::from("750"),
    }
}

#[test]
fn validate_accepts_linux_group_names() {
    let config = dir_config(String::from("/etc/openvpn/ccd"), "nogroup");
    assert!(config.validate().is_ok());

    let config = dir_config(String::from("/etc/openvpn/ccd"), "domain_users$");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_group_names_not_matching_api_schema() {
    let config = dir_config(String::from("/etc/openvpn/ccd"), "domain.users");
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_relative_paths() {
    let config = dir_config(String::from("etc/openvpn/ccd"), "nogroup");
    assert!(config.validate().is_err());
}

#[test]
fn remove_if_empty_removes_empty_directory() -> Result<()> {
    let dir = tmp_dir();
    fs::create_dir(&dir)?;

    let openvpn_dir = OpenVPNDir { dir: dir.clone() };
    openvpn_dir.remove_if_empty()?;

    assert!(!Path::new(&dir).exists());

    Ok(())
}

#[test]
fn remove_if_empty_ignores_non_empty_directory() -> Result<()> {
    let dir = tmp_dir();
    fs::create_dir(&dir)?;
    File::create(format!("{dir}/client"))?;

    let openvpn_dir = OpenVPNDir { dir: dir.clone() };
    openvpn_dir.remove_if_empty()?;

    assert!(Path::new(&dir).exists());

    fs::remove_file(format!("{dir}/client"))?;
    fs::remove_dir(dir)?;

    Ok(())
}

#[test]
fn remove_if_empty_ignores_missing_directory() -> Result<()> {
    let dir = tmp_dir();

    let openvpn_dir = OpenVPNDir { dir };
    openvpn_dir.remove_if_empty()?;

    Ok(())
}
