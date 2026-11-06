use super::*;
use serial_test::serial;
use uuid::Uuid;

#[test]
fn packaged_placeholder_cannot_be_used_as_an_api_key() -> std::io::Result<()> {
    let template = include_str!("../.env.example");
    let placeholder = template
        .lines()
        .find_map(|line| line.strip_prefix("API_KEY="))
        .unwrap()
        .trim_matches('"');
    assert!(placeholder.len() == 64);
    assert!(placeholder == API_KEY_PLACEHOLDER);
    let directory = tempfile::tempdir()?;
    let runtime = directory.path().to_string_lossy().into_owned();
    let mut cfg =
        Config::with_runtime_dirs(runtime.clone(), runtime.clone(), runtime.clone(), runtime)
            .unwrap();
    cfg.api_key = placeholder.to_owned();
    assert!(cfg.validate().is_err());
    cfg.api_key = "U".repeat(64);
    assert!(cfg.validate().is_ok());
    Ok(())
}

#[test]
#[serial]
fn removes_deprecated_openvpn_status_options_from_env_file() -> std::io::Result<()> {
    let path = format!("./tests/playground/tmp/.env_{}", Uuid::new_v4());
    fs::write(
        &path,
        [
            "API_KEY=\"test\"",
            "# Deprecated OpenVPN status files",
            "# Comma separated list of full paths of OpenVPN server status files",
            "OPENVPN_STATUS_FILES=\"/run/openvpn/server.status\"",
            "# Sampling interval in seconds for the OpenVPN status collector thread.",
            "OPENVPN_STATUS_SAMPLING_INTERVAL=30",
            "# Maximum number of lines returned per OpenVPN status request.",
            "OPENVPN_STATUS_REQUEST_MAX_LINES=1000",
            "# Maximum cache size for OpenVPN status content.",
            "OPENVPN_STATUS_CACHE_MAX_SIZE=10485760",
            "",
        ]
        .join("\n"),
    )?;

    env::set_var("OPENVPN_STATUS_FILES", "/run/openvpn/server.status");
    env::set_var("OPENVPN_STATUS_SAMPLING_INTERVAL", "30");
    env::set_var("OPENVPN_STATUS_REQUEST_MAX_LINES", "1000");
    env::set_var("OPENVPN_STATUS_CACHE_MAX_SIZE", "10485760");
    let removed = Config::remove_deprecated_openvpn_status_options(Path::new(&path))?;

    let data = fs::read_to_string(&path)?;
    assert_eq!(
        removed,
        vec![
            "OPENVPN_STATUS_FILES",
            "OPENVPN_STATUS_SAMPLING_INTERVAL",
            "OPENVPN_STATUS_REQUEST_MAX_LINES",
            "OPENVPN_STATUS_CACHE_MAX_SIZE"
        ]
    );
    assert!(!data.contains("OPENVPN_STATUS_FILES"));
    assert!(!data.contains("OPENVPN_STATUS_SAMPLING_INTERVAL"));
    assert!(!data.contains("OPENVPN_STATUS_REQUEST_MAX_LINES"));
    assert!(!data.contains("OPENVPN_STATUS_CACHE_MAX_SIZE"));
    assert!(!data.contains("Deprecated OpenVPN status files"));
    assert!(!data.contains("Comma separated list of full paths"));
    assert!(!data.contains("Sampling interval in seconds"));
    assert!(!data.contains("Maximum number of lines"));
    assert!(!data.contains("Maximum cache size"));
    assert!(env::var("OPENVPN_STATUS_FILES").is_err());
    assert!(env::var("OPENVPN_STATUS_SAMPLING_INTERVAL").is_err());
    assert!(env::var("OPENVPN_STATUS_REQUEST_MAX_LINES").is_err());
    assert!(env::var("OPENVPN_STATUS_CACHE_MAX_SIZE").is_err());

    fs::remove_file(path)?;
    Ok(())
}

#[test]
#[serial]
fn removes_commented_deprecated_openvpn_status_options_from_env_file() -> std::io::Result<()> {
    let path = format!("./tests/playground/tmp/.env_{}", Uuid::new_v4());
    fs::write(
        &path,
        [
            "API_KEY=\"test\"",
            "# Deprecated OpenVPN status files",
            "# Comma separated list of full paths of OpenVPN server status files",
            "# OPENVPN_STATUS_FILES=\"/run/openvpn/server.status\"",
            "# Sampling interval in seconds for the OpenVPN status collector thread.",
            "# OPENVPN_STATUS_SAMPLING_INTERVAL=30",
            "# Maximum number of lines returned per OpenVPN status request.",
            "# OPENVPN_STATUS_REQUEST_MAX_LINES=1000",
            "# Maximum cache size for OpenVPN status content.",
            "# OPENVPN_STATUS_CACHE_MAX_SIZE=10485760",
            "",
        ]
        .join("\n"),
    )?;

    env::set_var("OPENVPN_STATUS_FILES", "/run/openvpn/server.status");
    env::set_var("OPENVPN_STATUS_SAMPLING_INTERVAL", "30");
    env::set_var("OPENVPN_STATUS_REQUEST_MAX_LINES", "1000");
    env::set_var("OPENVPN_STATUS_CACHE_MAX_SIZE", "10485760");
    let removed = Config::remove_deprecated_openvpn_status_options(Path::new(&path))?;

    let data = fs::read_to_string(&path)?;
    assert_eq!(
        removed,
        vec![
            "OPENVPN_STATUS_FILES",
            "OPENVPN_STATUS_SAMPLING_INTERVAL",
            "OPENVPN_STATUS_REQUEST_MAX_LINES",
            "OPENVPN_STATUS_CACHE_MAX_SIZE"
        ]
    );
    assert!(!data.contains("OPENVPN_STATUS_FILES"));
    assert!(!data.contains("OPENVPN_STATUS_SAMPLING_INTERVAL"));
    assert!(!data.contains("OPENVPN_STATUS_REQUEST_MAX_LINES"));
    assert!(!data.contains("OPENVPN_STATUS_CACHE_MAX_SIZE"));
    assert!(!data.contains("Deprecated OpenVPN status files"));
    assert!(!data.contains("Comma separated list of full paths"));
    assert!(!data.contains("Sampling interval in seconds"));
    assert!(!data.contains("Maximum number of lines"));
    assert!(!data.contains("Maximum cache size"));
    assert!(env::var("OPENVPN_STATUS_FILES").is_err());
    assert!(env::var("OPENVPN_STATUS_SAMPLING_INTERVAL").is_err());
    assert!(env::var("OPENVPN_STATUS_REQUEST_MAX_LINES").is_err());
    assert!(env::var("OPENVPN_STATUS_CACHE_MAX_SIZE").is_err());

    fs::remove_file(path)?;
    Ok(())
}

#[test]
#[serial]
fn removes_extra_blank_line_after_deprecated_openvpn_status_files() -> std::io::Result<()> {
    let path = format!("./tests/playground/tmp/.env_{}", Uuid::new_v4());
    fs::write(
        &path,
        [
            "API_KEY=\"test\"",
            "",
            "# Comma separated list of paths allowed for a fwcloud.sh script.",
            "# FWCLOUD_SCRIPT_PATHS=\"/etc/fwcloud/fwcloud.sh,/config/scripts/post-config.d/fwcloud.sh\"",
            "",
            "# Deprecated OpenVPN status files",
            "# Comma separated list of full paths of OpenVPN server status files",
            "OPENVPN_STATUS_FILES=\"/run/openvpn/server.status\"",
            "",
            "# Sampling interval in seconds for the OpenVPN status collector thread.",
            "# OPENVPN_STATUS_SAMPLING_INTERVAL=30",
            "",
        ]
        .join("\n"),
    )?;

    let removed = Config::remove_deprecated_openvpn_status_options(Path::new(&path))?;

    let data = fs::read_to_string(&path)?;
    assert_eq!(
        removed,
        vec!["OPENVPN_STATUS_FILES", "OPENVPN_STATUS_SAMPLING_INTERVAL"]
    );
    assert!(!data.contains("OPENVPN_STATUS_FILES"));
    assert!(!data.contains("OPENVPN_STATUS_SAMPLING_INTERVAL"));
    assert!(!data.contains("\n\n\n"));
    assert!(data.contains("# FWCLOUD_SCRIPT_PATHS=\"/etc/fwcloud/fwcloud.sh,/config/scripts/post-config.d/fwcloud.sh\""));

    fs::remove_file(path)?;
    Ok(())
}
