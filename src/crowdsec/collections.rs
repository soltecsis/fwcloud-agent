/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use tokio::{fs, process::Command, time::timeout};
use uuid::Uuid;

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{
            COLLECTION_CONFLICT, COLLECTION_INVALID, COLLECTION_TAINTED, COMMAND_FAILED,
            OPERATION_TIMEOUT,
        },
        models::{
            CrowdSecCollection, CrowdSecCollectionAcquisition,
            CrowdSecCollectionAcquisitionState, CrowdSecCollectionOperation,
            CrowdSecCollectionOperationResponse, CrowdSecCollectionServiceReloadState,
            CrowdSecCollectionState, CrowdSecCollectionsResponse,
        },
    },
    errors::{FwcError, Result},
};

const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const CROWDSEC_COMMAND: &str = "/usr/bin/crowdsec";
pub const ACQUISITION_DIRECTORY: &str = "/etc/crowdsec/acquis.d";
const ACQUISITION_FILE: &str = "/etc/crowdsec/acquis.yaml";
const CROWDSEC_CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";
const DETECT_CONFIGURATION_PATH: &str = "/var/lib/crowdsec/data/detect.yaml";
const MANAGED_ACQUISITION_HEADER: &str = "# This acquisition file is managed by FWCloud.";
const MANAGED_ACQUISITION_COLLECTION_PREFIX: &str = "# Collection: ";
const MANAGED_ACQUISITION_LABEL_TYPE_PREFIX: &str = "# Parser type: ";
const MANAGED_ACQUISITION_MANUAL_REVIEW: &str = "# Manual review is required before configuring this acquisition.";
const MANAGED_ACQUISITION_CANDIDATE_LABEL_TYPE_PREFIX: &str = "# Candidate parser type: ";

pub async fn list(installed_only: bool) -> Result<CrowdSecCollectionsResponse> {
    let arguments = list_arguments(installed_only);
    let output = CrowdSecCommand::cscli(arguments)?.execute().await?;
    let value = serde_json::from_str::<serde_json::Value>(output.stdout()).map_err(|_| {
        FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec collection list")
    })?;

    Ok(CrowdSecCollectionsResponse {
        collections: collections_from_json(&value),
    })
}

pub async fn install(name: &str) -> Result<CrowdSecCollectionOperationResponse> {
    validate_collection_name(name)?;
    let collection = collection_by_name(name).await?;

    reject_tainted_collection(&collection)?;
    if collection.state == CrowdSecCollectionState::Installed {
        let acquisition = ensure_managed_acquisition(name).await?;
        return Ok(CrowdSecCollectionOperationResponse {
            operation: CrowdSecCollectionOperation::Install,
            collection: Some(name.to_string()),
            processed_collections: vec![],
            skipped_collections: vec![name.to_string()],
            acquisition: Some(acquisition),
            service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
            message: "CrowdSec collection is already installed".to_string(),
        });
    }

    execute_collection_command(&["collections", "install", name]).await?;
    let acquisition = ensure_managed_acquisition(name).await?;
    let service_reload = collection_service_reload_state().await;

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Install,
        collection: Some(name.to_string()),
        processed_collections: vec![name.to_string()],
        skipped_collections: vec![],
        acquisition: Some(acquisition),
        message: collection_operation_message("CrowdSec collection is installed", &service_reload),
        service_reload,
    })
}

pub async fn remove(name: &str) -> Result<CrowdSecCollectionOperationResponse> {
    validate_collection_name(name)?;

    let collection = collection_by_name(name).await?;
    reject_tainted_collection(&collection)?;

    if collection.state == CrowdSecCollectionState::Available {
        return Ok(CrowdSecCollectionOperationResponse {
            operation: CrowdSecCollectionOperation::Remove,
            collection: Some(name.to_string()),
            processed_collections: vec![],
            skipped_collections: vec![name.to_string()],
            acquisition: None,
            service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
            message: "CrowdSec collection is already absent".to_string(),
        });
    }

    execute_collection_command(&["collections", "remove", name]).await?;
    let service_reload = collection_service_reload_state().await;

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Remove,
        collection: Some(name.to_string()),
        processed_collections: vec![name.to_string()],
        skipped_collections: vec![],
        acquisition: None,
        message: collection_operation_message("CrowdSec collection is removed", &service_reload),
        service_reload,
    })
}

pub async fn update() -> Result<CrowdSecCollectionOperationResponse> {
    CrowdSecCommand::cscli(&["hub", "update"])?
        .execute()
        .await?;

    let collections = list(true).await?.collections;
    let mut processed_collections = Vec::new();
    let mut skipped_collections = Vec::new();

    for collection in collections {
        match collection.state {
            CrowdSecCollectionState::Installed => {
                validate_collection_name(&collection.name)?;
                execute_collection_command(&["collections", "upgrade", &collection.name]).await?;
                processed_collections.push(collection.name);
            }
            CrowdSecCollectionState::Tainted => skipped_collections.push(collection.name),
            _ => {}
        }
    }

    if !processed_collections.is_empty() {
        let service_reload = collection_service_reload_state().await;
        return Ok(collection_operation_response(
            CrowdSecCollectionOperation::Update,
            None,
            processed_collections,
            skipped_collections,
            service_reload,
            "CrowdSec Hub index and installed collections are updated",
        ));
    }

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Update,
        collection: None,
        processed_collections,
        skipped_collections,
        acquisition: None,
        service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
        message: "CrowdSec Hub index and installed collections are updated".to_string(),
    })
}

fn collection_operation_response(
    operation: CrowdSecCollectionOperation,
    collection: Option<String>,
    processed_collections: Vec<String>,
    skipped_collections: Vec<String>,
    service_reload: CrowdSecCollectionServiceReloadState,
    completed_mutation: &str,
) -> CrowdSecCollectionOperationResponse {
    CrowdSecCollectionOperationResponse {
        operation,
        collection,
        processed_collections,
        skipped_collections,
        acquisition: None,
        message: collection_operation_message(completed_mutation, &service_reload),
        service_reload,
    }
}

pub(crate) fn managed_acquisition_file_name(collection: &str) -> Result<String> {
    validate_collection_name(collection)?;
    Ok(format!("{}.yaml", collection.replace('/', "-")))
}

pub(crate) async fn ensure_managed_acquisition(
    collection: &str,
) -> Result<CrowdSecCollectionAcquisition> {
    let file_path = managed_acquisition_file_path(collection)?;
    match fs::read_to_string(&file_path).await {
        Ok(contents) => return managed_acquisition_from_contents(collection, &file_path, &contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(FwcError::from(error)),
    }

    let label_types = detected_file_acquisition_label_types(collection).await?;
    match label_types.as_slice() {
        [] => Ok(automatic_configuration_unavailable(collection, &file_path)),
        [label_type] => {
            write_initial_managed_acquisition(
                &file_path,
                &managed_acquisition_initial_contents(collection, label_type),
            )
            .await?;
            Ok(ready_managed_acquisition(collection, &file_path, label_type))
        }
        _ => {
            write_initial_managed_acquisition(
                &file_path,
                &manual_review_managed_acquisition_contents(collection, &label_types),
            )
            .await?;
            Ok(manual_review_required(collection, &file_path, label_types))
        }
    }
}

async fn write_initial_managed_acquisition(file_path: &str, contents: &str) -> Result<()> {
    fs::create_dir_all(ACQUISITION_DIRECTORY).await?;
    fs::write(file_path, contents).await?;
    Ok(())
}

fn automatic_configuration_unavailable(
    collection: &str,
    file_path: &str,
) -> CrowdSecCollectionAcquisition {
    CrowdSecCollectionAcquisition {
        collection: collection.to_string(),
        file_path: file_path.to_string(),
        state: CrowdSecCollectionAcquisitionState::AutomaticConfigurationUnavailable,
        label_type: None,
        candidate_label_types: vec![],
        log_paths: vec![],
        message: "No compatible file-based CrowdSec acquisition was detected automatically"
            .to_string(),
    }
}

fn ready_managed_acquisition(
    collection: &str,
    file_path: &str,
    label_type: &str,
) -> CrowdSecCollectionAcquisition {
    CrowdSecCollectionAcquisition {
        collection: collection.to_string(),
        file_path: file_path.to_string(),
        state: CrowdSecCollectionAcquisitionState::Ready,
        label_type: Some(label_type.to_string()),
        candidate_label_types: vec![],
        log_paths: vec![],
        message: "CrowdSec acquisition is managed by FWCloud".to_string(),
    }
}

fn manual_review_required(
    collection: &str,
    file_path: &str,
    candidate_label_types: Vec<String>,
) -> CrowdSecCollectionAcquisition {
    CrowdSecCollectionAcquisition {
        collection: collection.to_string(),
        file_path: file_path.to_string(),
        state: CrowdSecCollectionAcquisitionState::ManualReviewRequired,
        label_type: None,
        candidate_label_types,
        log_paths: vec![],
        message: "Several compatible CrowdSec parser types were detected and require manual review"
            .to_string(),
    }
}

pub async fn managed_acquisition(collection: &str) -> Result<CrowdSecCollectionAcquisition> {
    let file_path = managed_acquisition_file_path(collection)?;
    match fs::read_to_string(&file_path).await {
        Ok(contents) => managed_acquisition_from_contents(collection, &file_path, &contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let label_types = detected_file_acquisition_label_types(collection).await?;
            Ok(match label_types.as_slice() {
                [] => automatic_configuration_unavailable(collection, &file_path),
                [label_type] => ready_managed_acquisition(collection, &file_path, label_type),
                _ => manual_review_required(collection, &file_path, label_types),
            })
        }
        Err(error) => Err(FwcError::from(error)),
    }
}

pub async fn update_managed_acquisition(
    collection: &str,
    log_paths: &[String],
) -> Result<CrowdSecCollectionAcquisition> {
    ensure_managed_acquisition(collection).await?;
    let acquisition = managed_acquisition(collection).await?;
    if acquisition.state != CrowdSecCollectionAcquisitionState::Ready {
        return Err(FwcError::crowdsec(
            COLLECTION_INVALID,
            "CrowdSec acquisition cannot be configured automatically",
        ));
    }
    let log_paths = validated_log_paths(log_paths)?;
    reject_conflicting_log_paths(&acquisition.file_path, &log_paths).await?;
    let contents = managed_acquisition_contents(collection, acquisition.label_type.as_deref(), &log_paths)?;
    let previous_contents = fs::read(&acquisition.file_path).await?;

    write_validate_and_reload_acquisition(
        Path::new(&acquisition.file_path),
        contents.as_bytes(),
        &previous_contents,
    )
    .await?;

    Ok(CrowdSecCollectionAcquisition {
        log_paths,
        ..acquisition
    })
}

async fn write_validate_and_reload_acquisition(
    path: &Path,
    contents: &[u8],
    previous_contents: &[u8],
) -> Result<()> {
    write_acquisition_atomically(path, contents)?;

    if let Err(error) = validate_crowdsec_configuration().await {
        return restore_acquisition_after_validation_failure(path, previous_contents, error);
    }

    if reload_crowdsec_service().await.is_ok() {
        return Ok(());
    }

    match restore_acquisition_after_reload_failure(path, previous_contents).await {
        Ok(()) => Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec acquisition reload failed and the previous configuration was restored",
        )),
        Err(_) => Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec acquisition reload failed and automatic recovery failed",
        )),
    }
}

fn restore_acquisition_after_validation_failure(
    path: &Path,
    previous_contents: &[u8],
    validation_error: FwcError,
) -> Result<()> {
    write_acquisition_atomically(path, previous_contents).map_err(|_| {
        FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec acquisition validation failed and the previous configuration could not be restored",
        )
    })?;

    Err(validation_error)
}

async fn restore_acquisition_after_reload_failure(path: &Path, previous_contents: &[u8]) -> Result<()> {
    write_acquisition_atomically(path, previous_contents)?;
    reload_crowdsec_service().await
}

fn write_acquisition_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "CrowdSec acquisition directory is missing",
            )
        })?)?
        .sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }

    result.map_err(|_: std::io::Error| {
        FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to write CrowdSec acquisition configuration",
        )
    })
}

async fn validate_crowdsec_configuration() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(CROWDSEC_COMMAND).arg("-t").output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec configuration validation timed out"))?
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to validate CrowdSec configuration"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COLLECTION_INVALID,
            "CrowdSec acquisition configuration validation failed",
        ))
    }
}

async fn reject_conflicting_log_paths(target_path: &str, log_paths: &[String]) -> Result<()> {
    for acquisition_file in effective_acquisition_files().await? {
        if acquisition_file == Path::new(target_path) {
            continue;
        }

        let contents = fs::read_to_string(&acquisition_file).await?;
        if let Some(path) = conflicting_log_path(log_paths, &contents) {
            return Err(FwcError::CrowdSecCollectionAcquisitionPathConflict {
                path,
                conflicting_file_path: acquisition_file.display().to_string(),
            });
        }
    }

    Ok(())
}

async fn effective_acquisition_files() -> Result<Vec<PathBuf>> {
    let (acquisition_file, acquisition_directory) = configured_acquisition_locations().await?;
    let mut files = BTreeSet::new();

    if fs::try_exists(&acquisition_file).await? {
        files.insert(acquisition_file);
    }

    if !fs::try_exists(&acquisition_directory).await? {
        return Ok(files.into_iter().collect());
    }

    let mut entries = fs::read_dir(acquisition_directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let path = entry.path();
        let is_acquisition_file = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "yaml" | "yml"));

        if is_acquisition_file && (file_type.is_file() || file_type.is_symlink()) {
            files.insert(path);
        }
    }

    Ok(files.into_iter().collect())
}

async fn configured_acquisition_locations() -> Result<(PathBuf, PathBuf)> {
    let contents = match fs::read_to_string(CROWDSEC_CONFIG_PATH).await {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(FwcError::from(error)),
    };

    Ok((
        crowdsec_configuration_path(&contents, "acquisition_path")
            .unwrap_or_else(|| PathBuf::from(ACQUISITION_FILE)),
        crowdsec_configuration_path(&contents, "acquisition_dir")
            .unwrap_or_else(|| PathBuf::from(ACQUISITION_DIRECTORY)),
    ))
}

fn crowdsec_configuration_path(contents: &str, key: &str) -> Option<PathBuf> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }

        let (candidate, value) = line.split_once(':')?;
        if candidate.trim() != key {
            return None;
        }

        let value = value.trim();
        let value = if value.starts_with('"') {
            serde_json::from_str::<String>(value).ok()?
        } else {
            value.trim_matches('\'').to_string()
        };
        Path::new(&value).is_absolute().then_some(PathBuf::from(value))
    })
}

fn conflicting_log_path(log_paths: &[String], contents: &str) -> Option<String> {
    let declared_paths = log_paths_from_acquisition(contents);
    log_paths
        .iter()
        .find(|log_path| declared_paths.contains(log_path))
        .cloned()
}

fn managed_acquisition_file_path(collection: &str) -> Result<String> {
    Ok(format!(
        "{ACQUISITION_DIRECTORY}/{}",
        managed_acquisition_file_name(collection)?
    ))
}

async fn detected_file_acquisition_label_types(collection: &str) -> Result<Vec<String>> {
    let contents = fs::read_to_string(DETECT_CONFIGURATION_PATH)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                COMMAND_FAILED,
                "Unable to read CrowdSec service detection configuration",
            )
        })?;
    detected_file_acquisition_label_types_from_yaml(&contents, collection)
}

fn detected_file_acquisition_label_types_from_yaml(
    contents: &str,
    collection: &str,
) -> Result<Vec<String>> {
    let catalog = serde_yaml::from_str::<CrowdSecDetectionCatalog>(contents).map_err(|_| {
        FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to parse CrowdSec service detection configuration",
        )
    })?;

    let label_types = catalog
        .detect
        .into_values()
        .filter(|plan| plan.includes_collection(collection))
        .filter_map(|plan| plan.file_label_type())
        .collect::<BTreeSet<_>>();

    Ok(label_types.into_iter().collect())
}

fn managed_acquisition_initial_contents(collection: &str, label_type: &str) -> String {
    format!(
        "{}# Add log paths from FWCloud before enabling this acquisition.\n",
        managed_acquisition_metadata_contents(collection, label_type)
    )
}

fn manual_review_managed_acquisition_contents(
    collection: &str,
    candidate_label_types: &[String],
) -> String {
    let mut contents = format!(
        "{MANAGED_ACQUISITION_HEADER}\n\
         {MANAGED_ACQUISITION_COLLECTION_PREFIX}{collection}\n\
         {MANAGED_ACQUISITION_MANUAL_REVIEW}\n"
    );
    for label_type in candidate_label_types {
        contents.push_str(MANAGED_ACQUISITION_CANDIDATE_LABEL_TYPE_PREFIX);
        contents.push_str(label_type);
        contents.push('\n');
    }
    contents
}

fn managed_acquisition_metadata_contents(collection: &str, label_type: &str) -> String {
    format!(
        "{MANAGED_ACQUISITION_HEADER}\n\
         {MANAGED_ACQUISITION_COLLECTION_PREFIX}{collection}\n\
         {MANAGED_ACQUISITION_LABEL_TYPE_PREFIX}{label_type}\n"
    )
}

fn managed_acquisition_contents(
    collection: &str,
    label_type: Option<&str>,
    log_paths: &[String],
) -> Result<String> {
    let label_type = label_type.ok_or_else(|| {
        FwcError::crowdsec(
            COLLECTION_INVALID,
            "FWCloud managed CrowdSec acquisition has no parser type",
        )
    })?;
    let mut contents = if log_paths.is_empty() {
        managed_acquisition_initial_contents(collection, label_type)
    } else {
        managed_acquisition_metadata_contents(collection, label_type)
    };

    if !log_paths.is_empty() {
        contents.push_str("\nsource: file\nfilenames:\n");
        for log_path in log_paths {
            contents.push_str("  - ");
            contents.push_str(&yaml_string(log_path)?);
            contents.push('\n');
        }
        contents.push_str("labels:\n  type: ");
        contents.push_str(&yaml_string(label_type)?);
        contents.push('\n');
    }

    Ok(contents)
}

fn yaml_string(value: &str) -> Result<String> {
    serde_json::to_string(value).map_err(|_| {
        FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to serialize CrowdSec acquisition configuration",
        )
    })
}

fn managed_acquisition_from_contents(
    collection: &str,
    file_path: &str,
    contents: &str,
) -> Result<CrowdSecCollectionAcquisition> {
    let mut managed = false;
    let mut managed_collection = None;
    let mut label_type = None;
    let mut manual_review = false;
    let mut candidate_label_types = BTreeSet::new();

    for line in contents.lines() {
        if line == MANAGED_ACQUISITION_HEADER {
            managed = true;
        } else if let Some(value) = line.strip_prefix(MANAGED_ACQUISITION_COLLECTION_PREFIX) {
            managed_collection = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix(MANAGED_ACQUISITION_LABEL_TYPE_PREFIX) {
            label_type = Some(value.to_string());
        } else if line == MANAGED_ACQUISITION_MANUAL_REVIEW {
            manual_review = true;
        } else if let Some(value) = line.strip_prefix(MANAGED_ACQUISITION_CANDIDATE_LABEL_TYPE_PREFIX)
        {
            candidate_label_types.insert(value.to_string());
        }
    }

    if !managed || managed_collection.as_deref() != Some(collection) {
        return Err(FwcError::crowdsec(
            COLLECTION_INVALID,
            "CrowdSec acquisition is not managed by FWCloud",
        ));
    }

    if manual_review {
        return Ok(manual_review_required(
            collection,
            file_path,
            candidate_label_types.into_iter().collect(),
        ));
    }

    match label_type {
        Some(label_type) => {
            let mut acquisition = ready_managed_acquisition(collection, file_path, &label_type);
            acquisition.log_paths = log_paths_from_acquisition(contents);
            Ok(acquisition)
        }
        None => Ok(automatic_configuration_unavailable(collection, file_path)),
    }
}

fn log_paths_from_acquisition(contents: &str) -> Vec<String> {
    let mut filenames_indent = None;
    let mut log_paths = Vec::new();

    for line in contents.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        if line.trim() == "filenames:" {
            filenames_indent = Some(indent);
            continue;
        }

        let Some(filenames_indent_value) = filenames_indent else {
            continue;
        };
        if indent <= filenames_indent_value {
            filenames_indent = None;
            continue;
        }

        let value = line.trim_start().strip_prefix("- ");
        if let Some(value) = value.and_then(yaml_string_value) {
            log_paths.push(value);
        }
    }

    log_paths
}

fn yaml_string_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with('"') {
        serde_json::from_str(value).ok()
    } else {
        Some(value.to_string())
    }
}

fn validated_log_paths(log_paths: &[String]) -> Result<Vec<String>> {
    let mut validated = Vec::with_capacity(log_paths.len());

    for log_path in log_paths {
        let valid = !log_path.is_empty()
            && log_path == log_path.trim()
            && log_path.len() <= 1024
            && !log_path.chars().any(char::is_control)
            && Path::new(log_path).is_absolute();
        if !valid {
            return Err(FwcError::crowdsec(
                COLLECTION_INVALID,
                "Invalid CrowdSec acquisition log path",
            ));
        }

        if !validated.contains(log_path) {
            validated.push(log_path.to_string());
        }
    }

    Ok(validated)
}

#[derive(Deserialize)]
struct CrowdSecDetectionCatalog {
    #[serde(default)]
    detect: BTreeMap<String, CrowdSecDetectionPlan>,
}

#[derive(Deserialize)]
struct CrowdSecDetectionPlan {
    #[serde(default)]
    hub_spec: CrowdSecDetectionHubSpec,
    acquisition_spec: Option<CrowdSecDetectionAcquisitionSpec>,
}

impl CrowdSecDetectionPlan {
    fn includes_collection(&self, collection: &str) -> bool {
        self.hub_spec
            .collections
            .iter()
            .any(|candidate| candidate == collection)
    }

    fn file_label_type(&self) -> Option<String> {
        let datasource = self.acquisition_spec.as_ref()?.datasource.as_ref()?;
        (datasource.source == "file")
            .then(|| datasource.labels.as_ref()?.label_type.clone())
            .flatten()
            .filter(|label_type| !label_type.is_empty())
    }
}

#[derive(Default, Deserialize)]
struct CrowdSecDetectionHubSpec {
    #[serde(default)]
    collections: Vec<String>,
}

#[derive(Deserialize)]
struct CrowdSecDetectionAcquisitionSpec {
    datasource: Option<CrowdSecDetectedDatasource>,
}

#[derive(Deserialize)]
struct CrowdSecDetectedDatasource {
    source: String,
    labels: Option<CrowdSecDetectedLabels>,
}

#[derive(Deserialize)]
struct CrowdSecDetectedLabels {
    #[serde(rename = "type")]
    label_type: Option<String>,
}

fn list_arguments(installed_only: bool) -> &'static [&'static str] {
    if installed_only {
        &["collections", "list", "-o", "json"]
    } else {
        &["collections", "list", "--all", "-o", "json"]
    }
}

fn validate_collection_name(name: &str) -> Result<()> {
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment.len() <= 64
            && segment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
    };
    let mut segments = name.split('/');
    let valid = name.len() <= 129
        && segments.next().is_some_and(valid_segment)
        && segments.next().is_some_and(valid_segment)
        && segments.next().is_none();

    if valid {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COLLECTION_INVALID,
            "Invalid CrowdSec collection name",
        ))
    }
}

async fn collection_by_name(name: &str) -> Result<CrowdSecCollection> {
    list(false)
        .await?
        .collections
        .into_iter()
        .find(|collection| collection.name == name)
        .ok_or_else(|| {
            FwcError::crowdsec(
                COLLECTION_INVALID,
                "CrowdSec collection is not available in the installed Hub",
            )
        })
}

fn reject_tainted_collection(collection: &CrowdSecCollection) -> Result<()> {
    if collection.state == CrowdSecCollectionState::Tainted {
        Err(FwcError::crowdsec(
            COLLECTION_TAINTED,
            "CrowdSec collection has local changes",
        ))
    } else {
        Ok(())
    }
}

async fn execute_collection_command(arguments: &[&str]) -> Result<()> {
    let output = CrowdSecCommand::cscli(arguments)?
        .execute_allow_failure()
        .await?;

    if output.succeeded() {
        Ok(())
    } else {
        Err(collection_command_error(output.stderr()))
    }
}

fn collection_command_error(diagnostics: &str) -> FwcError {
    let diagnostics = diagnostics.to_ascii_lowercase();

    if diagnostics.contains("tainted") {
        FwcError::crowdsec(COLLECTION_TAINTED, "CrowdSec collection has local changes")
    } else if diagnostics.contains("dependency")
        || diagnostics.contains("conflict")
        || diagnostics.contains("required by")
    {
        FwcError::crowdsec(
            COLLECTION_CONFLICT,
            "CrowdSec collection dependency conflict",
        )
    } else {
        FwcError::crowdsec(COMMAND_FAILED, "CrowdSec collection command failed")
    }
}

async fn reload_crowdsec_service() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["reload", "crowdsec.service"])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec service command timed out"))?
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to run CrowdSec service command"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec service command failed",
        ))
    }
}

async fn collection_service_reload_state() -> CrowdSecCollectionServiceReloadState {
    collection_service_reload_state_from_result(reload_crowdsec_service().await)
}

fn collection_service_reload_state_from_result(
    result: Result<()>,
) -> CrowdSecCollectionServiceReloadState {
    match result {
        Ok(()) => CrowdSecCollectionServiceReloadState::Reloaded,
        Err(_) => CrowdSecCollectionServiceReloadState::Failed,
    }
}

fn collection_operation_message(
    completed_mutation: &str,
    service_reload: &CrowdSecCollectionServiceReloadState,
) -> String {
    match service_reload {
        CrowdSecCollectionServiceReloadState::Reloaded => {
            format!("{completed_mutation} and CrowdSec service is reloaded")
        }
        CrowdSecCollectionServiceReloadState::Failed => {
            format!("{completed_mutation}, but CrowdSec service reload failed")
        }
    }
}

fn collections_from_json(value: &serde_json::Value) -> Vec<CrowdSecCollection> {
    let values = match value {
        serde_json::Value::Array(values) => values,
        serde_json::Value::Object(values) => values
            .get("collections")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        _ => &[],
    };

    let mut collections = values
        .iter()
        .filter_map(collection_from_json)
        .collect::<Vec<_>>();
    collections.sort_by(|left, right| left.name.cmp(&right.name));
    collections
}

fn collection_from_json(value: &serde_json::Value) -> Option<CrowdSecCollection> {
    let values = value.as_object()?;
    let name = values.get("name")?.as_str()?.to_string();
    let status = values.get("status").and_then(serde_json::Value::as_str);
    let installed = values
        .get("installed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| status.is_some_and(|status| status.contains("enabled")));
    let tainted = values
        .get("tainted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| status.is_some_and(|status| status.contains("tainted")));
    let disabled = status.is_some_and(|status| status.contains("disabled"));

    let local_version =
        string_value(values, "local_version").or_else(|| string_value(values, "localversion"));
    let state = if tainted {
        CrowdSecCollectionState::Tainted
    } else if installed {
        CrowdSecCollectionState::Installed
    } else if disabled {
        CrowdSecCollectionState::Disabled
    } else {
        CrowdSecCollectionState::Available
    };

    Some(CrowdSecCollection {
        name,
        version: if state == CrowdSecCollectionState::Installed {
            local_version.or_else(|| string_value(values, "version"))
        } else {
            None
        },
        state,
        available: true,
        path: string_value(values, "local_path")
            .or_else(|| string_value(values, "path"))
            .or_else(|| string_value(values, "remote_path")),
    })
}

fn string_value(values: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    values
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        collection_command_error, collection_from_json, collection_operation_response,
        collection_service_reload_state_from_result, detected_file_acquisition_label_types_from_yaml,
        conflicting_log_path, crowdsec_configuration_path, list_arguments,
        managed_acquisition_contents, managed_acquisition_file_name,
        managed_acquisition_from_contents, managed_acquisition_initial_contents,
        manual_review_managed_acquisition_contents, automatic_configuration_unavailable,
        validated_log_paths, validate_collection_name,
    };
    use crate::{
        crowdsec::{
            errors::{COLLECTION_CONFLICT, COLLECTION_INVALID, COLLECTION_TAINTED},
            models::{
                CrowdSecCollectionOperation, CrowdSecCollectionOperationResponse,
                CrowdSecCollectionAcquisitionState, CrowdSecCollectionServiceReloadState,
                CrowdSecCollectionState,
            },
        },
        errors::FwcError,
    };

    #[test]
    fn accepts_only_safe_two_segment_collection_names() {
        assert!(validate_collection_name("crowdsecurity/sshd").is_ok());

        for name in [
            "crowdsecurity",
            "crowdsecurity/sshd/extra",
            "crowdsecurity/ssh d",
            "crowdsecurity/../sshd",
            "crowdsecurity/sshd\n",
        ] {
            let error = validate_collection_name(name).unwrap_err();
            assert!(matches!(
                error,
                FwcError::CrowdSec {
                    code: COLLECTION_INVALID,
                    ..
                }
            ));
        }
    }

    #[test]
    fn omits_remote_version_for_available_collections() {
        let collection = collection_from_json(&json!({
            "name": "crowdsecurity/sshd",
            "version": "0.2"
        }))
        .unwrap();

        assert_eq!(collection.version, None);
        assert_eq!(collection.state, CrowdSecCollectionState::Available);
    }

    #[test]
    fn omits_stale_local_version_for_uninstalled_collections() {
        for value in [
            json!({
                "name": "crowdsecurity/sshd",
                "local_version": "0.2"
            }),
            json!({
                "name": "crowdsecurity/sshd",
                "local_version": "0.2",
                "status": "disabled"
            }),
            json!({
                "name": "crowdsecurity/sshd",
                "local_version": "0.2",
                "status": "tainted"
            }),
        ] {
            let collection = collection_from_json(&value).unwrap();

            assert_ne!(collection.state, CrowdSecCollectionState::Installed);
            assert_eq!(collection.version, None);
        }
    }

    #[test]
    fn normalizes_cscli_collection_output() {
        let collection = collection_from_json(&json!({
            "name": "crowdsecurity/sshd",
            "local_version": "0.2",
            "local_path": "/etc/crowdsec/collections/sshd.yaml",
            "status": "enabled"
        }))
        .unwrap();

        assert_eq!(collection.name, "crowdsecurity/sshd");
        assert_eq!(collection.version.as_deref(), Some("0.2"));
        assert_eq!(collection.state, CrowdSecCollectionState::Installed);
        assert!(collection.available);
        assert_eq!(
            collection.path.as_deref(),
            Some("/etc/crowdsec/collections/sshd.yaml")
        );
    }

    #[test]
    fn maps_tainted_and_dependency_diagnostics_to_stable_errors() {
        let tainted = collection_command_error("collection is tainted");
        let conflict = collection_command_error("required by another collection");

        assert!(matches!(
            tainted,
            FwcError::CrowdSec {
                code: COLLECTION_TAINTED,
                ..
            }
        ));
        assert!(matches!(
            conflict,
            FwcError::CrowdSec {
                code: COLLECTION_CONFLICT,
                ..
            }
        ));
    }

    #[test]
    fn uses_fixed_arguments_for_collection_lists() {
        assert_eq!(
            list_arguments(false),
            ["collections", "list", "--all", "-o", "json"]
        );
        assert_eq!(list_arguments(true), ["collections", "list", "-o", "json"]);
    }

    #[test]
    fn omits_absent_collection_and_sensitive_fields_from_update_response() {
        let response = CrowdSecCollectionOperationResponse {
            operation: CrowdSecCollectionOperation::Update,
            collection: None,
            processed_collections: vec!["crowdsecurity/sshd".to_string()],
            skipped_collections: vec![],
            acquisition: None,
            service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
            message: "CrowdSec Hub index and installed collections are updated".to_string(),
        };
        let response = serde_json::to_value(response).unwrap();

        assert!(response.get("collection").is_none());
        assert_eq!(
            response["processed_collections"],
            json!(["crowdsecurity/sshd"])
        );
        assert_eq!(response["service_reload"], json!("reloaded"));
        assert!(response.get("api_key").is_none());
        assert!(response.get("enrollment_key").is_none());
    }

    #[test]
    fn normalizes_managed_acquisition_file_names() {
        assert_eq!(
            managed_acquisition_file_name("crowdsecurity/nginx").unwrap(),
            "crowdsecurity-nginx.yaml"
        );
    }

    #[test]
    fn reads_only_file_acquisitions_for_the_requested_collection_from_detect_catalog() {
        let catalog = r#"
detect:
  nginx-file:
    hub_spec:
      collections:
        - crowdsecurity/nginx
    acquisition_spec:
      datasource:
        source: file
        labels:
          type: nginx
  sshd-file:
    hub_spec:
      collections:
        - crowdsecurity/sshd
    acquisition_spec:
      datasource:
        source: file
        labels:
          type: syslog
  nginx-journal:
    hub_spec:
      collections:
        - crowdsecurity/nginx
    acquisition_spec:
      datasource:
        source: journalctl
        labels:
          type: nginx
"#;

        assert_eq!(
            detected_file_acquisition_label_types_from_yaml(catalog, "crowdsecurity/nginx")
                .unwrap(),
            vec!["nginx"]
        );
    }

    #[test]
    fn creates_comment_only_managed_acquisition_contents() {
        assert_eq!(
            managed_acquisition_initial_contents("crowdsecurity/nginx", "nginx"),
            "# This acquisition file is managed by FWCloud.\n\
             # Collection: crowdsecurity/nginx\n\
             # Parser type: nginx\n\
             # Add log paths from FWCloud before enabling this acquisition.\n"
        );
    }

    #[test]
    fn reports_automatic_configuration_unavailable_without_file_detection() {
        let acquisition = automatic_configuration_unavailable(
            "crowdsecurity/sshd",
            "/etc/crowdsec/acquis.d/crowdsecurity-sshd.yaml",
        );

        assert_eq!(
            acquisition.state,
            CrowdSecCollectionAcquisitionState::AutomaticConfigurationUnavailable
        );
        assert!(acquisition.label_type.is_none());
    }

    #[test]
    fn keeps_ambiguous_file_detections_inactive_for_manual_review() {
        let contents = manual_review_managed_acquisition_contents(
            "crowdsecurity/nginx",
            &["nginx".to_string(), "openresty".to_string()],
        );
        let acquisition = managed_acquisition_from_contents(
            "crowdsecurity/nginx",
            "/etc/crowdsec/acquis.d/crowdsecurity-nginx.yaml",
            &contents,
        )
        .unwrap();

        assert_eq!(
            acquisition.state,
            CrowdSecCollectionAcquisitionState::ManualReviewRequired
        );
        assert_eq!(
            acquisition.candidate_label_types,
            vec!["nginx".to_string(), "openresty".to_string()]
        );
        assert!(acquisition.label_type.is_none());
        assert!(!contents.contains("source: file"));
    }

    #[test]
    fn reads_only_fwcloud_managed_acquisition_log_paths() {
        let contents = managed_acquisition_contents(
            "crowdsecurity/nginx",
            Some("nginx"),
            &["/var/log/nginx/access.log".to_string()],
        )
        .unwrap();
        let acquisition = managed_acquisition_from_contents(
            "crowdsecurity/nginx",
            "/etc/crowdsec/acquis.d/crowdsecurity-nginx.yaml",
            &contents,
        )
        .unwrap();

        assert_eq!(acquisition.label_type.as_deref(), Some("nginx"));
        assert_eq!(
            acquisition.log_paths,
            vec!["/var/log/nginx/access.log".to_string()]
        );
    }

    #[test]
    fn rejects_invalid_or_duplicate_managed_acquisition_log_paths() {
        assert!(validated_log_paths(&["relative.log".to_string()]).is_err());
        assert!(validated_log_paths(&["/var/log/access.log\n".to_string()]).is_err());
        assert_eq!(
            validated_log_paths(&[
                "/var/log/nginx/access.log".to_string(),
                "/var/log/nginx/access.log".to_string(),
            ])
            .unwrap(),
            vec!["/var/log/nginx/access.log".to_string()]
        );
    }

    #[test]
    fn detects_log_path_conflicts_in_external_acquisitions() {
        let contents = "source: file\nfilenames:\n  - /var/log/nginx/access.log\n";

        assert_eq!(
            conflicting_log_path(&["/var/log/nginx/access.log".to_string()], contents),
            Some("/var/log/nginx/access.log".to_string())
        );
    }

    #[test]
    fn reads_configured_acquisition_locations() {
        let configuration = r#"crowdsec_service:
  acquisition_path: /srv/acquis.yaml
  acquisition_dir: "/srv/acquis.d"
"#;

        assert_eq!(
            crowdsec_configuration_path(configuration, "acquisition_path"),
            Some("/srv/acquis.yaml".into())
        );
        assert_eq!(
            crowdsec_configuration_path(configuration, "acquisition_dir"),
            Some("/srv/acquis.d".into())
        );
    }

    #[test]
    fn reports_completed_collection_mutations_when_service_reload_fails() {
        for (operation, collection, processed_collections) in [
            (
                CrowdSecCollectionOperation::Install,
                Some("crowdsecurity/sshd".to_string()),
                vec!["crowdsecurity/sshd".to_string()],
            ),
            (
                CrowdSecCollectionOperation::Remove,
                Some("crowdsecurity/nginx".to_string()),
                vec!["crowdsecurity/nginx".to_string()],
            ),
            (
                CrowdSecCollectionOperation::Update,
                None,
                vec!["crowdsecurity/linux".to_string()],
            ),
        ] {
            let response = collection_operation_response(
                operation,
                collection,
                processed_collections,
                vec![],
                CrowdSecCollectionServiceReloadState::Failed,
                "CrowdSec collection mutation completed",
            );
            let response = serde_json::to_value(response).unwrap();

            assert_eq!(response["service_reload"], json!("failed"));
            assert_eq!(response["processed_collections"].as_array().unwrap().len(), 1);
            assert!(response["message"]
                .as_str()
                .unwrap()
                .contains("CrowdSec service reload failed"));
            assert!(response.get("api_key").is_none());
            assert!(response.get("enrollment_key").is_none());
        }
    }

    #[test]
    fn maps_service_reload_errors_to_a_failed_state() {
        let state = collection_service_reload_state_from_result(Err(FwcError::crowdsec(
            COLLECTION_INVALID,
            "CrowdSec service command failed",
        )));

        assert_eq!(state, CrowdSecCollectionServiceReloadState::Failed);
    }
}
