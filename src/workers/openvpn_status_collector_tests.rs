use super::*;
use crate::errors::Result;
use std::env;
use uuid::Uuid;

struct TestCollector {
    inner: OpenVPNStCollectorInner,
    root: tempfile::TempDir,
}
impl std::ops::Deref for TestCollector {
    type Target = OpenVPNStCollectorInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl std::ops::DerefMut for TestCollector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl Drop for TestCollector {
    fn drop(&mut self) {
        let _ = remove_collector_files(&self.inner);
    }
}
fn config_fixture() -> (tempfile::TempDir, Config) {
    let root = tempfile::Builder::new()
        .prefix("collector-")
        .tempdir_in("tests/playground/tmp")
        .unwrap();
    let path = |name| root.path().join(name).to_str().unwrap().to_owned();
    let config =
        Config::with_runtime_dirs(path("etc"), path("tmp"), path("data"), path("plugins")).unwrap();
    (root, config)
}
fn collector_factory(options: Vec<(&str, String)>, _change_paths: bool) -> TestCollector {
    let (root, cfg) = config_fixture();
    let value = |name| {
        options
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    };
    let files = value("OPENVPN_STATUS_FILES").unwrap_or("");
    OpenVPNStatusSamplingConfig {
        status_files: files
            .split(',')
            .filter(|file| !file.is_empty())
            .map(|path| OpenVPNStatusFileConfig {
                path: path.trim().into(),
                sampling_interval: value("OPENVPN_STATUS_SAMPLING_INTERVAL")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_SAMPLING_INTERVAL),
                request_max_lines: value("OPENVPN_STATUS_REQUEST_MAX_LINES")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_REQUEST_MAX_LINES),
                cache_max_size: value("OPENVPN_STATUS_CACHE_MAX_SIZE")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_CACHE_MAX_SIZE),
            })
            .collect(),
    }
    .save(&cfg.etc_dir)
    .unwrap();
    TestCollector {
        inner: OpenVPNStCollectorInner::new(&cfg),
        root,
    }
}

fn status_files_list_factory(n: usize) -> Vec<String> {
    let mut list: Vec<String> = vec![];

    for _ in 0..n {
        list.push(format!(
            "{}/tests/playground/tmp/{}.log",
            env::current_dir().unwrap().display(),
            Uuid::new_v4()
        ));
    }

    list
}

fn structured_status_file(
    delimiter: char,
    update: &str,
    update_timestamp: u64,
    bytes: u64,
) -> String {
    let separator = delimiter.to_string();
    [
        format!("TITLE{separator}OpenVPN 2.6.0"),
        format!("TIME{separator}{update}{separator}{update_timestamp}"),
        format!("HEADER{separator}CLIENT_LIST{separator}Common Name{separator}Real Address{separator}Virtual Address{separator}Virtual IPv6 Address{separator}Bytes Received{separator}Bytes Sent{separator}Connected Since{separator}Connected Since (time_t)"),
        format!("CLIENT_LIST{separator}client{separator}1.1.1.1:1194{separator}10.0.0.2{separator}{separator}{bytes}{separator}20{separator}2023-07-21 15:01:00{separator}1689951660"),
        format!("HEADER{separator}ROUTING_TABLE{separator}Virtual Address{separator}Common Name{separator}Real Address{separator}Last Ref"),
    ]
    .join("\n")
}

fn remove_collector_files(collector: &OpenVPNStCollectorInner) -> Result<()> {
    for inx in 0..collector.len() {
        if Path::new(&collector.openvpn_status_files[inx].st_file).is_file() {
            fs::remove_file(&collector.openvpn_status_files[inx].st_file)?;
        }
        if Path::new(&collector.openvpn_status_files[inx].tmp_file).is_file() {
            fs::remove_file(&collector.openvpn_status_files[inx].tmp_file)?;
        }
        if Path::new(&collector.openvpn_status_files[inx].cache_file).is_file() {
            fs::remove_file(&collector.openvpn_status_files[inx].cache_file)?;
        }
    }

    Ok(())
}

#[test]
fn generates_empty_openvpn_status_file_vector_without_api_config() {
    let collector = collector_factory(vec![], false);
    assert_eq!(collector.openvpn_status_files.len(), 0);
}

#[test]
fn empty_openvpn_status_file_vector_if_config_option_is_empty() {
    let collector = collector_factory(vec![("OPENVPN_STATUS_FILES", String::from(""))], false);
    assert_eq!(collector.openvpn_status_files.len(), 0);
}

#[test]
fn customized_openvpn_status_files_config() {
    let n = 3;
    let list = status_files_list_factory(n);
    let collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], false);
    assert_eq!(collector.openvpn_status_files.len(), n);

    for (inx, file) in list.iter().enumerate() {
        assert_eq!(&collector.openvpn_status_files[inx].st_file, file);
        assert_eq!(
            collector.openvpn_status_files[inx].tmp_file,
            format!(
                "{}/tmp/{}.tmp",
                collector.root.path().display(),
                file.replace('/', "_")
            )
        );
        assert_eq!(
            collector.openvpn_status_files[inx].cache_file,
            format!(
                "{}/data/{}.data",
                collector.root.path().display(),
                file.replace('/', "_")
            )
        );
        assert_eq!(collector.openvpn_status_files[inx].last_update, 0);
        assert_eq!(
            collector.openvpn_status_files[inx].sampling_interval,
            DEFAULT_SAMPLING_INTERVAL
        );
        assert_eq!(
            collector.openvpn_status_files[inx].cache_max_size,
            DEFAULT_CACHE_MAX_SIZE
        );
    }
}

#[test]
fn should_apply_api_sampling_parameters_per_file() -> Result<()> {
    let (_root, cfg) = config_fixture();
    let api_config_file = OpenVPNStatusSamplingConfig::path(&cfg.etc_dir);
    let list = status_files_list_factory(2);

    OpenVPNStatusSamplingConfig {
        status_files: vec![
            OpenVPNStatusFileConfig {
                path: list[0].clone(),
                sampling_interval: 10,
                request_max_lines: 200,
                cache_max_size: 1024,
            },
            OpenVPNStatusFileConfig {
                path: list[1].clone(),
                sampling_interval: 45,
                request_max_lines: 500,
                cache_max_size: 2097152,
            },
        ],
    }
    .save(&cfg.etc_dir)?;

    let collector = OpenVPNStCollectorInner::new(&cfg);
    assert_eq!(collector.openvpn_status_files.len(), 2);
    assert_eq!(collector.openvpn_status_files[0].st_file, list[0]);
    assert_eq!(collector.openvpn_status_files[0].sampling_interval, 10);
    assert_eq!(collector.openvpn_status_files[0].cache_max_size, 1024);
    assert_eq!(collector.openvpn_status_files[1].st_file, list[1]);
    assert_eq!(collector.openvpn_status_files[1].sampling_interval, 45);
    assert_eq!(collector.openvpn_status_files[1].cache_max_size, 2097152);

    let config = OpenVPNStatusSamplingConfig::load(&cfg.etc_dir)?.unwrap();
    assert_eq!(config.request_max_lines_for_path(&list[0]), 200);
    assert_eq!(config.request_max_lines_for_path(&list[1]), 500);
    assert_eq!(
        config.request_max_lines_for_path("/run/openvpn/missing.status"),
        DEFAULT_REQUEST_MAX_LINES
    );

    fs::remove_file(api_config_file)?;
    Ok(())
}

#[test]
fn should_wait_for_file_sampling_interval() -> Result<()> {
    let list = status_files_list_factory(1);
    let mut collector = collector_factory(
        vec![
            ("OPENVPN_STATUS_SAMPLING_INTERVAL", String::from("2")),
            ("OPENVPN_STATUS_FILES", list.join(",")),
        ],
        true,
    );

    fs::copy(
        "./tests/templates/openvpn-status.log_ts1",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(false);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);
    assert_eq!(
        collector.openvpn_status_files[0].seconds_until_next_sample,
        2
    );

    fs::copy(
        "./tests/templates/openvpn-status.log_ts2",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(false);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);
    assert_eq!(
        collector.openvpn_status_files[0].seconds_until_next_sample,
        1
    );

    collector.collect_all_files_data(false);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);
    assert_eq!(
        collector.openvpn_status_files[0].seconds_until_next_sample,
        2
    );

    remove_collector_files(&collector)?;
    Ok(())
}

#[test]
fn should_ignore_fist_sample_set() -> Result<()> {
    let list = status_files_list_factory(1);
    let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);

    fs::copy(
        "./tests/templates/openvpn-status.log_ts1",
        &collector.openvpn_status_files[0].st_file,
    )?;

    collector.collect_all_files_data(true);

    // This is the first data collection, and then the cache file should be created but with 0 bytes.
    let size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 0);
    // The last_updated timestamp must be updated with the one into the OpenVPN status file.
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

    remove_collector_files(&collector)?;
    Ok(())
}

#[test]
fn should_append_to_cache_file_if_timestamp_changes() -> Result<()> {
    let list = status_files_list_factory(1);
    let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);

    fs::copy(
        "./tests/templates/openvpn-status.log_ts1",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);

    // This is the first data collection, and then the cache file should be created but with 0 bytes.
    let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 0);
    // The last_updated timestamp must be updated with the one into the OpenVPN status file.
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

    // Change the status file by a new one with different timestamp.
    fs::copy(
        "./tests/templates/openvpn-status.log_ts2",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 262);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

    // Change the status file by a new one with different timestamp.
    fs::copy(
        "./tests/templates/openvpn-status.log_ts3",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 524);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366496);

    // Change the status file by a new one with lower timestamp.
    fs::copy(
        "./tests/templates/openvpn-status.log_ts1",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 786);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

    remove_collector_files(&collector)?;
    Ok(())
}

#[test]
fn should_not_append_to_cache_file_if_timestamp_is_equal() -> Result<()> {
    let list = status_files_list_factory(1);
    let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);

    fs::copy(
        "./tests/templates/openvpn-status.log_ts1",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);

    // This is the first data collection, and then the cache file should be created but with 0 bytes.
    let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 0);
    // The last_updated timestamp must be updated with the one into the OpenVPN status file.
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

    // Change the status file by a new one with different timestamp.
    fs::copy(
        "./tests/templates/openvpn-status.log_ts2",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 262);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

    // Don't change OpenVPN status log file, then timestamp is the same.
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 262);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

    remove_collector_files(&collector)?;
    Ok(())
}

#[test]
fn control_cache_file_size() -> Result<()> {
    let list = status_files_list_factory(1);
    let mut collector = collector_factory(
        vec![
            ("OPENVPN_STATUS_CACHE_MAX_SIZE", String::from("1")),
            ("OPENVPN_STATUS_FILES", list.join(",")),
        ],
        true,
    );

    fs::copy(
        "./tests/templates/openvpn-status.log_ts1",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 0);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

    fs::copy(
        "./tests/templates/openvpn-status.log_ts2",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    assert_eq!(size, 262);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

    fs::copy(
        "./tests/templates/openvpn-status.log_ts3",
        &collector.openvpn_status_files[0].st_file,
    )?;
    collector.collect_all_files_data(true);
    size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
    // The cache file size control takes effect and no more status data is collected.
    assert_eq!(size, 262);
    assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

    remove_collector_files(&collector)?;
    Ok(())
}

#[test]
fn should_convert_to_correct_timestamp_with_old_datetime_format() {
    assert_eq!(
        OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch("Fri Jul 21 14:35:56 2023"),
        Some(1689950156)
    );
}

#[test]
fn should_convert_to_correct_timestamp_with_new_datetime_format() {
    assert_eq!(
        OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch("2023-07-21 15:02:00"),
        Some(1689951720)
    );
}

#[test]
fn should_return_none_with_an_invalid_datetime_string() {
    assert_eq!(
        OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch("Invalid datetime string"),
        None
    );
}

#[test]
fn should_detect_openvpn_status_file_formats() {
    let v1 = vec![
        String::from("OpenVPN CLIENT LIST"),
        String::from("Updated,2026-08-10 10:00:00"),
        String::from("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"),
    ];
    let v2 = vec![
        String::from("TITLE,OpenVPN 2.6.0"),
        String::from("HEADER,CLIENT_LIST,Common Name,Real Address"),
    ];
    let v3 = vec![
        String::from("TITLE\tOpenVPN 2.6.0"),
        String::from("HEADER\tCLIENT_LIST\tCommon Name\tReal Address"),
    ];

    assert_eq!(
        OpenVPNStCollectorInner::detect_status_format(&v1),
        Some(OpenVPNStatusFormat::V1)
    );
    assert_eq!(
        OpenVPNStCollectorInner::detect_status_format(&v2),
        Some(OpenVPNStatusFormat::V2)
    );
    assert_eq!(
        OpenVPNStCollectorInner::detect_status_format(&v3),
        Some(OpenVPNStatusFormat::V3)
    );
}

#[test]
fn should_reject_unrecognized_openvpn_status_file_format() {
    assert_eq!(
        OpenVPNStCollectorInner::detect_status_format(&[String::from("invalid")]),
        None
    );
}

#[test]
fn should_parse_v1_status_file() -> Result<()> {
    let lines = fs::read_to_string("./tests/templates/openvpn-status.log_ts1")?
        .lines()
        .map(String::from)
        .collect::<Vec<String>>();

    let (sample_timestamp, sessions) =
        OpenVPNStCollectorInner::parse_v1_status(&lines).map_err(std::io::Error::other)?;

    assert_eq!(sample_timestamp, 1633366402);
    assert_eq!(sessions.len(), 4);
    assert_eq!(sessions[0].common_name, "FWCLOD-VPN-01");
    assert_eq!(sessions[0].real_address, "1.1.1.1:43501");
    assert_eq!(sessions[0].bytes_received, 22394454);
    assert_eq!(sessions[0].bytes_sent, 22553788);
    assert_eq!(sessions[0].connected_since, 1632487691);
    assert_eq!(sessions[0].sample_timestamp, sample_timestamp);

    Ok(())
}

#[test]
fn should_parse_v1_status_file_with_new_datetime_format() {
    let lines = vec![
        String::from("OpenVPN CLIENT LIST"),
        String::from("Updated,2023-07-21 15:02:00"),
        String::from("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"),
        String::from("client,1.1.1.1:1194,10,20,2023-07-21 15:02:00"),
        String::from("ROUTING TABLE"),
    ];

    let (sample_timestamp, sessions) = OpenVPNStCollectorInner::parse_v1_status(&lines).unwrap();

    assert_eq!(sample_timestamp, 1689951720);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].connected_since, 1689951720);
}

#[test]
fn should_parse_v2_status_file() {
    let lines = vec![
        String::from("TITLE,OpenVPN 2.6.0"),
        String::from("TIME,2023-07-21 15:02:00,1689951720"),
        String::from("HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher"),
        String::from("CLIENT_LIST,client,1.1.1.1:1194,10.0.0.2,,10,20,2023-07-21 15:01:00,1689951660,user,1,2,AES-256-GCM"),
        String::from("HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref"),
    ];

    let (sample_timestamp, sessions) = OpenVPNStCollectorInner::parse_v2_status(&lines).unwrap();

    assert_eq!(sample_timestamp, 1689951720);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].common_name, "client");
    assert_eq!(sessions[0].real_address, "1.1.1.1:1194");
    assert_eq!(sessions[0].bytes_received, 10);
    assert_eq!(sessions[0].bytes_sent, 20);
    assert_eq!(sessions[0].connected_since, 1689951660);
}

#[test]
fn should_parse_v3_status_file() {
    let lines = vec![
        String::from("TITLE\tOpenVPN 2.6.0"),
        String::from("TIME\t2023-07-21 15:02:00\t1689951720"),
        String::from("HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher"),
        String::from("CLIENT_LIST\tclient\t1.1.1.1:1194\t10.0.0.2\t\t10\t20\t2023-07-21 15:01:00\t1689951660\tuser\t1\t2\tAES-256-GCM"),
        String::from("HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref"),
    ];

    let (sample_timestamp, sessions) = OpenVPNStCollectorInner::parse_v3_status(&lines).unwrap();

    assert_eq!(sample_timestamp, 1689951720);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].common_name, "client");
    assert_eq!(sessions[0].real_address, "1.1.1.1:1194");
    assert_eq!(sessions[0].bytes_received, 10);
    assert_eq!(sessions[0].bytes_sent, 20);
    assert_eq!(sessions[0].connected_since, 1689951660);
}

#[test]
fn should_normalize_all_status_formats_to_the_same_cache_record() {
    let v1 = vec![
        String::from("OpenVPN CLIENT LIST"),
        String::from("Updated,2023-07-21 15:02:00"),
        String::from("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"),
        String::from("client,1.1.1.1:1194,10,20,2023-07-21 15:01:00"),
        String::from("ROUTING TABLE"),
    ];
    let v2 = vec![
        String::from("TITLE,OpenVPN 2.6.0"),
        String::from("TIME,2023-07-21 15:02:00,1689951720"),
        String::from("HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t)"),
        String::from("CLIENT_LIST,client,1.1.1.1:1194,10.0.0.2,,10,20,2023-07-21 15:01:00,1689951660"),
        String::from("HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref"),
    ];
    let v3 = vec![
        String::from("TITLE\tOpenVPN 2.6.0"),
        String::from("TIME\t2023-07-21 15:02:00\t1689951720"),
        String::from("HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)"),
        String::from("CLIENT_LIST\tclient\t1.1.1.1:1194\t10.0.0.2\t\t10\t20\t2023-07-21 15:01:00\t1689951660"),
        String::from("HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref"),
    ];

    let (_, v1_sessions) = OpenVPNStCollectorInner::parse_v1_status(&v1).unwrap();
    let (_, v2_sessions) = OpenVPNStCollectorInner::parse_v2_status(&v2).unwrap();
    let (_, v3_sessions) = OpenVPNStCollectorInner::parse_v3_status(&v3).unwrap();

    assert_eq!(v1_sessions, v2_sessions);
    assert_eq!(v2_sessions, v3_sessions);
    assert_eq!(
        v1_sessions[0].to_cache_record(),
        "1689951720,client,1.1.1.1:1194,10,20,1689951660"
    );
}

#[test]
fn should_parse_structured_status_samples() {
    let v2 = structured_status_file(',', "2023-07-21 15:02:00", 1689951720, 22394454)
        .lines()
        .map(String::from)
        .collect::<Vec<String>>();
    let v3 = structured_status_file('\t', "2023-07-21 15:02:00", 1689951720, 22394454)
        .lines()
        .map(String::from)
        .collect::<Vec<String>>();

    let (_, v2_sessions) = OpenVPNStCollectorInner::parse_v2_status(&v2).unwrap();
    let (_, v3_sessions) = OpenVPNStCollectorInner::parse_v3_status(&v3).unwrap();

    assert_eq!(v2_sessions, v3_sessions);
    assert_eq!(
        v2_sessions[0].to_cache_record(),
        "1689951720,client,1.1.1.1:1194,22394454,20,1689951660"
    );
}

#[test]
fn should_parse_structured_status_with_reordered_extended_columns() {
    for delimiter in [',', '\t'] {
        let separator = delimiter.to_string();
        let lines = vec![
            format!("TITLE{separator}OpenVPN 2.6.0"),
            format!("TIME{separator}2023-07-21 15:02:00{separator}1689951720"),
            format!("HEADER{separator}CLIENT_LIST{separator}Username{separator}Bytes Sent{separator}Common Name{separator}Connected Since (time_t){separator}Real Address{separator}Bytes Received{separator}Connected Since{separator}Peer ID{separator}Data Channel Cipher"),
            format!("CLIENT_LIST{separator}fwcloud{separator}20{separator}client{separator}1689951660{separator}1.1.1.1:1194{separator}10{separator}2023-07-21 15:01:00{separator}2{separator}AES-256-GCM"),
            format!("HEADER{separator}ROUTING_TABLE{separator}Virtual Address"),
        ];

        let (_, sessions) =
            OpenVPNStCollectorInner::parse_structured_status(&lines, delimiter).unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].common_name, "client");
        assert_eq!(sessions[0].real_address, "1.1.1.1:1194");
        assert_eq!(sessions[0].bytes_received, 10);
        assert_eq!(sessions[0].bytes_sent, 20);
        assert_eq!(sessions[0].connected_since, 1689951660);
    }
}

#[test]
fn should_preserve_sampling_semantics_for_structured_status_formats() -> Result<()> {
    for delimiter in [',', '\t'] {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(
            vec![
                ("OPENVPN_STATUS_CACHE_MAX_SIZE", String::from("1")),
                ("OPENVPN_STATUS_FILES", list.join(",")),
            ],
            true,
        );
        let status_file = collector.openvpn_status_files[0].st_file.clone();
        let cache_file = collector.openvpn_status_files[0].cache_file.clone();

        fs::write(
            &status_file,
            structured_status_file(delimiter, "2023-07-21 15:02:00", 1689951720, 10),
        )?;
        collector.collect_all_files_data(true);
        assert_eq!(fs::metadata(&cache_file)?.len(), 0);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1689951720);

        fs::write(
            &status_file,
            structured_status_file(delimiter, "2023-07-21 15:03:00", 1689951780, 30),
        )?;
        collector.collect_all_files_data(true);
        let cached_status = fs::read_to_string(&cache_file)?;
        assert_eq!(
            cached_status,
            "1689951780,client,1.1.1.1:1194,30,20,1689951660\n"
        );
        assert_eq!(collector.openvpn_status_files[0].last_update, 1689951780);

        collector.collect_all_files_data(true);
        assert_eq!(fs::read_to_string(&cache_file)?, cached_status);

        fs::write(
            &status_file,
            structured_status_file(delimiter, "2023-07-21 15:04:00", 1689951840, 50),
        )?;
        collector.collect_all_files_data(true);
        assert_eq!(fs::read_to_string(&cache_file)?, cached_status);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1689951780);

        remove_collector_files(&collector)?;
    }

    Ok(())
}

#[test]
fn should_not_write_partial_cache_for_malformed_structured_status_files() -> Result<()> {
    for delimiter in [',', '\t'] {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);
        let status_file = collector.openvpn_status_files[0].st_file.clone();
        let tmp_file = collector.openvpn_status_files[0].tmp_file.clone();
        let cache_file = collector.openvpn_status_files[0].cache_file.clone();

        fs::write(
            &status_file,
            structured_status_file(delimiter, "2023-07-21 15:02:00", 1689951720, 22394454),
        )?;
        collector.collect_all_files_data(true);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1689951720);

        let malformed_status =
            structured_status_file(delimiter, "2023-07-21 15:03:00", 1689951780, 22394454)
                .replace("22394454", "invalid");
        fs::write(&status_file, malformed_status)?;
        collector.collect_all_files_data(true);

        assert_eq!(fs::metadata(&cache_file)?.len(), 0);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1689951720);
        assert!(!Path::new(&tmp_file).is_file());

        remove_collector_files(&collector)?;
    }

    Ok(())
}
