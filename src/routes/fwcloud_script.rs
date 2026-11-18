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
use std::sync::Arc;

use crate::config::Config;
use crate::utils::http_files::HttpFiles;

use crate::errors::{FwcError, Result};

#[derive(Serialize)]
pub struct PolicyScriptBackup {
    pub path: String,
    pub compilation_date: Option<String>,
    pub installation_date: Option<String>,
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

            let (compilation_date, installation_date) = policy_script_dates(&path)?;
            backups.push(PolicyScriptBackup {
                path: path.to_string_lossy().to_string(),
                compilation_date,
                installation_date,
            });
        }
    }

    for path in active_paths {
        if !path.is_file() {
            continue;
        }

        let (compilation_date, installation_date) = policy_script_dates(&path)?;
        backups.push(PolicyScriptBackup {
            path: path.to_string_lossy().to_string(),
            compilation_date,
            installation_date,
        });
    }

    backups.sort_by(|left, right| right.path.cmp(&left.path));

    Ok(backups)
}

fn policy_script_dates(path: &Path) -> Result<(Option<String>, Option<String>)> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut compilation_date = None;
    let mut installation_date = None;

    for line in reader.lines() {
        let line = line?;
        if let Some(value) = line.strip_prefix("FWCLOUD_COMPILATION_DATE=") {
            compilation_date = Some(value.trim_matches('"').to_string());
        } else if let Some(value) = line.strip_prefix("FWCLOUD_INSTALLATION_DATE=") {
            installation_date = Some(value.trim_matches('"').to_string());
        }

        if compilation_date.is_some() && installation_date.is_some() {
            break;
        }
    }

    Ok((compilation_date, installation_date))
}

fn policy_script_path(path: &str, script_paths: &[String]) -> Option<std::path::PathBuf> {
    let path = Path::new(path);
    if !path.is_file() {
        return None;
    }

    let path = path.canonicalize().ok()?;
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
    let content = fs::read_to_string(path)?;

    Ok(HttpResponse::Ok().json(PolicyScriptContent { content }))
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
