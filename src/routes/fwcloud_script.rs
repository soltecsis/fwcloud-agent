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

use actix_multipart::Multipart;
use actix_web::{get, post, web, HttpResponse};
use log::debug;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::config::Config;
use crate::utils::http_files::HttpFiles;

use crate::errors::{FwcError, Result};

#[derive(Serialize)]
pub struct PolicyScriptBackup {
    pub path: String,
    pub compilation_date: String,
    pub installation_date: String,
}

#[derive(Deserialize)]
pub struct PolicyScriptContentRequest {
    pub file: String,
}

#[derive(Serialize)]
pub struct PolicyScriptContent {
    pub content: String,
}

#[derive(Deserialize)]
pub struct PolicyScriptComparisonRequest {
    pub file1: String,
    pub file2: String,
}

#[derive(Serialize)]
pub struct PolicyScriptComparison {
    pub diff: String,
}

lazy_static! {
    static ref POLICY_SCRIPT_BACKUP_NAME: Regex = Regex::new(r"^fwcloud-\d{14}\.sh$").unwrap();
}

fn policy_script_backups(script_paths: &[String]) -> Result<Vec<PolicyScriptBackup>> {
    let active_paths: HashSet<_> = script_paths
        .iter()
        .map(|script_path| Path::new(script_path).to_path_buf())
        .collect();
    let directories: HashSet<_> = script_paths
        .iter()
        .filter_map(|script_path| Path::new(script_path).parent().map(Path::to_path_buf))
        .collect();
    let mut backups: Vec<PolicyScriptBackup> = vec![];

    for directory in directories {
        if !directory.is_dir() {
            continue;
        }

        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }

            let path = entry.path();
            let file_name = match path.file_name().and_then(|file_name| file_name.to_str()) {
                Some(file_name) => file_name,
                None => continue,
            };
            if !POLICY_SCRIPT_BACKUP_NAME.is_match(file_name) {
                continue;
            }

            if let Some((compilation_date, installation_date)) = policy_script_dates(&path)? {
                backups.push(PolicyScriptBackup {
                    path: path.to_string_lossy().to_string(),
                    compilation_date,
                    installation_date,
                });
            }
        }
    }

    for path in active_paths {
        if !path.is_file() {
            continue;
        }

        if let Some((compilation_date, installation_date)) = policy_script_dates(&path)? {
            backups.push(PolicyScriptBackup {
                path: path.to_string_lossy().to_string(),
                compilation_date,
                installation_date,
            });
        }
    }

    backups.sort_by(|left, right| right.path.cmp(&left.path));

    Ok(backups)
}

fn policy_script_dates(path: &Path) -> Result<Option<(String, String)>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut compilation_date = None;
    let mut installation_date = None;

    for line in reader.lines().take(25) {
        let line = line?;
        if let Some(value) = line.strip_prefix("FWCLOUD_COMPILATION_DATE=") {
            compilation_date = Some(value.trim_matches('"').to_string());
        } else if let Some(value) = line.strip_prefix("FWCLOUD_INSTALLATION_DATE=") {
            installation_date = Some(value.trim_matches('"').to_string());
        }

        if compilation_date.is_some() && installation_date.is_some() {
            let compilation_date = compilation_date.unwrap();
            let installation_date = installation_date.unwrap();
            if compilation_date.is_empty() || installation_date.is_empty() {
                return Ok(None);
            }
            return Ok(Some((compilation_date, installation_date)));
        }
    }

    Ok(None)
}

fn policy_script_path(path: &str, script_paths: &[String]) -> Option<std::path::PathBuf> {
    let path = Path::new(path);
    if !path.is_file() {
        return None;
    }

    let path = path.canonicalize().ok()?;
    policy_script_dates(&path).ok().flatten()?;
    let active_script =
        script_paths
            .iter()
            .any(|script_path| match Path::new(script_path).canonicalize() {
                Ok(script_path) => script_path == path,
                Err(_) => false,
            });
    if active_script {
        return Some(path);
    }

    let file_name = path.file_name()?.to_str()?;
    if !POLICY_SCRIPT_BACKUP_NAME.is_match(file_name) {
        return None;
    }

    let parent = path.parent()?;
    script_paths.iter().find_map(|script_path| {
        Path::new(script_path)
            .parent()
            .and_then(|directory| directory.canonicalize().ok())
            .filter(|directory| directory == parent)
            .map(|_| path.clone())
    })
}

fn policy_script_content(path: &Path) -> Result<PolicyScriptContent> {
    Ok(PolicyScriptContent {
        content: fs::read_to_string(path)?,
    })
}

fn policy_script_diff(file1: &Path, file2: &Path) -> Result<PolicyScriptComparison> {
    let output = Command::new("diff").arg(file1).arg(file2).output()?;

    match output.status.code() {
        Some(0) | Some(1) => Ok(PolicyScriptComparison {
            diff: String::from_utf8_lossy(&output.stdout).to_string(),
        }),
        _ => Err(FwcError::CmdExitStatusNotZero),
    }
}

#[get("/fwcloud_script/history")]
async fn history(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(policy_script_backups(&cfg.fwcloud_script_paths)?))
}

#[post("/fwcloud_script/content")]
async fn content(
    request: web::Json<PolicyScriptContentRequest>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    let path = policy_script_path(&request.file, &cfg.fwcloud_script_paths)
        .ok_or_else(|| FwcError::BadRequest(String::from("Invalid policy script path")))?;

    Ok(HttpResponse::Ok().json(policy_script_content(&path)?))
}

#[post("/fwcloud_script/diff")]
async fn diff(
    request: web::Json<PolicyScriptComparisonRequest>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    let file1 = policy_script_path(&request.file1, &cfg.fwcloud_script_paths)
        .ok_or_else(|| FwcError::BadRequest(String::from("Invalid policy script path")))?;
    let file2 = policy_script_path(&request.file2, &cfg.fwcloud_script_paths)
        .ok_or_else(|| FwcError::BadRequest(String::from("Invalid policy script path")))?;

    Ok(HttpResponse::Ok().json(policy_script_diff(&file1, &file2)?))
}

#[post("/fwcloud_script/upload")]
async fn upload_and_run(payload: Multipart, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let res: HttpResponse;

    // Mutex scope start.
    {
        debug!("Locking script mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.fwcloud_script);
        let _mutex_data = mutex.lock().await;
        debug!("Script mutex locked (thread id: {})", thread_id::get());

        res = HttpFiles::new(cfg.tmp_dir, false)
            .fwcloud_script(payload, &cfg)
            .await?;

        debug!("Releasing script mutex (thread id: {})", thread_id::get());
    } // End of mutex scope.

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn create_tmp_dir() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("fwcloud-agent-policy-history-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_policy(path: &Path, compilation_date: Option<&str>, installation_date: Option<&str>) {
        let mut script_content = String::from("#!/bin/sh\n");
        if let Some(compilation_date) = compilation_date {
            script_content.push_str(&format!(
                "FWCLOUD_COMPILATION_DATE=\"{compilation_date}\"\n"
            ));
        }
        if let Some(installation_date) = installation_date {
            script_content.push_str(&format!(
                "FWCLOUD_INSTALLATION_DATE=\"{installation_date}\"\n"
            ));
        }
        fs::write(path, script_content).unwrap();
    }

    #[test]
    fn policy_script_backups_include_active_script_and_metadata() {
        let tmp_dir = create_tmp_dir();
        let active_path = tmp_dir.join("fwcloud.sh");
        let backup_path = tmp_dir.join("fwcloud-20261118120000.sh");
        write_policy(
            &active_path,
            Some("2026-11-18 11:59:00"),
            Some("2026-11-18 12:00:00"),
        );
        write_policy(
            &backup_path,
            Some("2026-11-18 08:59:00"),
            Some("2026-11-18 09:00:00"),
        );
        fs::write(tmp_dir.join("unrelated.sh"), "#!/bin/sh\n").unwrap();

        let backups = policy_script_backups(&[active_path.to_string_lossy().to_string()]).unwrap();

        assert_eq!(backups.len(), 2);
        let active = backups
            .iter()
            .find(|backup| backup.path == active_path.to_string_lossy())
            .unwrap();
        assert_eq!(active.compilation_date.as_str(), "2026-11-18 11:59:00");
        assert_eq!(active.installation_date.as_str(), "2026-11-18 12:00:00");
        let backup = backups
            .iter()
            .find(|backup| backup.path == backup_path.to_string_lossy())
            .unwrap();
        assert_eq!(backup.compilation_date.as_str(), "2026-11-18 08:59:00");
        assert_eq!(backup.installation_date.as_str(), "2026-11-18 09:00:00");

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_script_backups_ignore_scripts_without_complete_metadata_in_the_header() {
        let tmp_dir = create_tmp_dir();
        let active_path = tmp_dir.join("fwcloud.sh");
        let backup_path = tmp_dir.join("fwcloud-20261118120000.sh");
        let late_metadata_path = tmp_dir.join("fwcloud-20261118130000.sh");
        let empty_metadata_path = tmp_dir.join("fwcloud-20261118140000.sh");
        write_policy(
            &active_path,
            Some("2026-11-18 11:59:00"),
            Some("2026-11-18 12:00:00"),
        );
        write_policy(&backup_path, Some("2026-11-18 11:00:00"), None);
        write_policy(&empty_metadata_path, Some("2026-11-18 11:00:00"), Some(""));
        fs::write(
            &late_metadata_path,
            format!(
                "{}FWCLOUD_COMPILATION_DATE=\"2026-11-18 12:59:00\"\nFWCLOUD_INSTALLATION_DATE=\"2026-11-18 13:00:00\"\n",
                "# header\n".repeat(25)
            ),
        )
        .unwrap();

        let backups = policy_script_backups(&[active_path.to_string_lossy().to_string()]).unwrap();

        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].path, active_path.to_string_lossy());
        assert!(policy_script_path(
            &backup_path.to_string_lossy(),
            &[active_path.to_string_lossy().to_string()]
        )
        .is_none());
        assert!(policy_script_path(
            &late_metadata_path.to_string_lossy(),
            &[active_path.to_string_lossy().to_string()]
        )
        .is_none());
        assert!(policy_script_path(
            &empty_metadata_path.to_string_lossy(),
            &[active_path.to_string_lossy().to_string()]
        )
        .is_none());

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_script_backups_ignore_missing_directories() {
        let tmp_dir = create_tmp_dir();
        let path = tmp_dir.join("missing/fwcloud.sh");

        assert!(policy_script_backups(&[path.to_string_lossy().to_string()])
            .unwrap()
            .is_empty());

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_script_path_only_allows_active_and_backup_scripts() {
        let tmp_dir = create_tmp_dir();
        let active_path = tmp_dir.join("fwcloud.sh");
        let backup_path = tmp_dir.join("fwcloud-20261118120000.sh");
        let other_path = tmp_dir.join("other.sh");
        write_policy(&active_path, Some("date"), Some("date"));
        write_policy(&backup_path, Some("date"), Some("date"));
        write_policy(&other_path, None, None);
        let script_paths = vec![active_path.to_string_lossy().to_string()];

        assert_eq!(
            policy_script_path(&active_path.to_string_lossy(), &script_paths),
            Some(active_path.canonicalize().unwrap())
        );
        assert_eq!(
            policy_script_path(&backup_path.to_string_lossy(), &script_paths),
            Some(backup_path.canonicalize().unwrap())
        );
        write_policy(&backup_path, Some("date"), Some(""));
        assert_eq!(
            policy_script_path(&backup_path.to_string_lossy(), &script_paths),
            None
        );
        assert_eq!(
            policy_script_path(&other_path.to_string_lossy(), &script_paths),
            None
        );

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_script_content_and_diff_preserve_read_only_behavior() {
        let tmp_dir = create_tmp_dir();
        let file1 = tmp_dir.join("fwcloud.sh");
        let file2 = tmp_dir.join("fwcloud-20261118120000.sh");
        fs::write(&file1, "same\n").unwrap();
        fs::write(&file2, "same\n").unwrap();

        assert_eq!(policy_script_content(&file1).unwrap().content, "same\n");
        assert!(policy_script_diff(&file1, &file2).unwrap().diff.is_empty());

        fs::write(&file2, "different\n").unwrap();
        assert!(policy_script_diff(&file1, &file2)
            .unwrap()
            .diff
            .contains("different"));

        fs::remove_dir_all(tmp_dir).unwrap();
    }
}
