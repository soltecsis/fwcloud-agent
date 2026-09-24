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

use std::sync::Arc;

use actix_web::{delete, get, post, web, HttpResponse};
use log::debug;

use crate::{
    config::Config,
    crowdsec::{
        alerts, bouncers, collections, console, decisions, install, lapi,
        models::{
            CrowdSecAlertsQuery, CrowdSecBouncerInstallRequest, CrowdSecBouncerRegisterRequest,
            CrowdSecBouncerUninstallRequest, CrowdSecCentralLapiConfigureRequest,
            CrowdSecCollectionInstallRequest, CrowdSecCollectionRemoveRequest,
            CrowdSecCollectionUpdateRequest, CrowdSecCollectionsQuery,
            CrowdSecConsoleEnrollRequest, CrowdSecDecisionsFlushRequest, CrowdSecDecisionsQuery,
            CrowdSecInstallMode, CrowdSecInstallRequest, CrowdSecLapiReplicationReadinessResponse,
            CrowdSecRemoteMachineActivationRequest, CrowdSecRemoteMachineReauthenticationRequest,
            CrowdSecRemoteMachineResumeRequest, CrowdSecUninstallRequest,
        },
        progress::{CrowdSecProgress, CrowdSecProgressMessageType},
        status, uninstall,
    },
    errors::Result,
};

#[post("/crowdsec/transitions/preflight")]
async fn preflight_crowdsec_transition(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<crate::crowdsec::transitions::TransitionPrepareRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let _guard = cfg.mutex.crowdsec.lock().await;
    match crate::crowdsec::transitions::preflight(&request, &progress).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(error) => {
            progress.typed_message(
                CrowdSecProgressMessageType::Error,
                "CrowdSec transition validation failed",
            );
            Err(error)
        }
    }
}

#[post("/crowdsec/transitions/prepare")]
async fn prepare_crowdsec_transition(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<crate::crowdsec::transitions::TransitionPrepareRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let _guard = cfg.mutex.crowdsec.lock().await;
    if !request.authority_changed
        && request.expected.mode == crate::crowdsec::transitions::TransitionMode::Machine
        && request.target.mode == crate::crowdsec::transitions::TransitionMode::Machine
        && request.expected.local_remediation != request.target.local_remediation
    {
        Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remediation::prepare(cfg.data_dir, &request, &progress)
                .await?,
        ))
    } else if request.authority_changed
        && request.target.mode == crate::crowdsec::transitions::TransitionMode::Machine
    {
        Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remote::prepare(cfg.data_dir, &request, &progress)
                .await?,
        ))
    } else if request.authority_changed
        && request.target.mode == crate::crowdsec::transitions::TransitionMode::Lapi
    {
        Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::local_lapi::prepare(cfg.data_dir, &request, &progress)
                .await?,
        ))
    } else {
        Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::address::prepare(cfg.data_dir, &request, &progress)
                .await?,
        ))
    }
}

#[post("/crowdsec/transitions/activate")]
async fn activate_crowdsec_transition(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<crate::crowdsec::transitions::TransitionActivateRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let _guard = cfg.mutex.crowdsec.lock().await;
    if request.transition_id.is_nil() {
        return Err(crate::errors::FwcError::crowdsec(
            crate::crowdsec::errors::TRANSITION_INVALID,
            "A transition identifier is required",
        ));
    }
    match crate::crowdsec::transitions::kind(cfg.data_dir, request.transition_id).await? {
        crate::crowdsec::transitions::TransitionKind::Address => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::address::activate(cfg.data_dir, &request, &progress)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Remote => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remote::activate(cfg.data_dir, &request, &progress)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Remediation => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remediation::activate(cfg.data_dir, &request, &progress)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Lapi => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::local_lapi::activate(cfg.data_dir, &request, &progress)
                .await?,
        )),
    }
}

#[get("/crowdsec/transitions/{id}")]
async fn crowdsec_transition(
    cfg: web::Data<Arc<Config>>,
    id: web::Path<uuid::Uuid>,
) -> Result<HttpResponse> {
    let _guard = cfg.mutex.crowdsec.lock().await;
    match crate::crowdsec::transitions::kind(cfg.data_dir, *id).await? {
        crate::crowdsec::transitions::TransitionKind::Address => Ok(HttpResponse::Ok()
            .json(crate::crowdsec::transitions::address::load(cfg.data_dir, *id).await?)),
        crate::crowdsec::transitions::TransitionKind::Remote => Ok(HttpResponse::Ok()
            .json(crate::crowdsec::transitions::remote::load(cfg.data_dir, *id).await?)),
        crate::crowdsec::transitions::TransitionKind::Remediation => Ok(HttpResponse::Ok()
            .json(crate::crowdsec::transitions::remediation::load(cfg.data_dir, *id).await?)),
        crate::crowdsec::transitions::TransitionKind::Lapi => Ok(HttpResponse::Ok()
            .json(crate::crowdsec::transitions::local_lapi::load(cfg.data_dir, *id).await?)),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionConfirmation {
    transition_id: uuid::Uuid,
    confirm: bool,
}

#[post("/crowdsec/transitions/recover")]
async fn recover_crowdsec_transition(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<TransitionConfirmation>,
) -> Result<HttpResponse> {
    let _guard = cfg.mutex.crowdsec.lock().await;
    if !request.confirm {
        return Err(crate::errors::FwcError::crowdsec(
            crate::crowdsec::errors::TRANSITION_INVALID,
            "Explicit confirmation is required",
        ));
    }
    match crate::crowdsec::transitions::kind(cfg.data_dir, request.transition_id).await? {
        crate::crowdsec::transitions::TransitionKind::Address => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::address::recover(cfg.data_dir, request.transition_id)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Remote => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remote::recover(cfg.data_dir, request.transition_id)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Remediation => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remediation::recover(cfg.data_dir, request.transition_id)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Lapi => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::local_lapi::recover(cfg.data_dir, request.transition_id)
                .await?,
        )),
    }
}

#[post("/crowdsec/transitions/finalize")]
async fn finalize_crowdsec_transition(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<TransitionConfirmation>,
) -> Result<HttpResponse> {
    let _guard = cfg.mutex.crowdsec.lock().await;
    if !request.confirm {
        return Err(crate::errors::FwcError::crowdsec(
            crate::crowdsec::errors::TRANSITION_INVALID,
            "Explicit confirmation is required",
        ));
    }
    match crate::crowdsec::transitions::kind(cfg.data_dir, request.transition_id).await? {
        crate::crowdsec::transitions::TransitionKind::Address => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::address::finalize(cfg.data_dir, request.transition_id)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Remote => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remote::finalize(cfg.data_dir, request.transition_id)
                .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Remediation => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::remediation::finalize(
                cfg.data_dir,
                request.transition_id,
            )
            .await?,
        )),
        crate::crowdsec::transitions::TransitionKind::Lapi => Ok(HttpResponse::Ok().json(
            crate::crowdsec::transitions::local_lapi::finalize(cfg.data_dir, request.transition_id)
                .await?,
        )),
    }
}

#[get("/crowdsec/status")]
async fn crowdsec_status(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let status_result = status::status().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        status_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/crowdsec/collections")]
async fn crowdsec_collections(
    cfg: web::Data<Arc<Config>>,
    query: web::Query<CrowdSecCollectionsQuery>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let collections_result = collections::list(query.installed.unwrap_or(false)).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        collections_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/collections/install")]
async fn install_crowdsec_collection(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecCollectionInstallRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let install_result = collections::install(&request.name).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        install_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/collections/remove")]
async fn remove_crowdsec_collection(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecCollectionRemoveRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let remove_result = collections::remove(&request.name).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        remove_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/collections/update")]
async fn update_crowdsec_collections(
    cfg: web::Data<Arc<Config>>,
    _request: web::Json<CrowdSecCollectionUpdateRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let update_result = collections::update().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        update_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/crowdsec/console/status")]
async fn crowdsec_console_status(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let status_result = console::status().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        status_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/console/enroll")]
async fn enroll_crowdsec_console(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecConsoleEnrollRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let enroll_result = console::enroll(
            &request.enrollment_key,
            request.name.as_deref(),
            request.tags.as_deref(),
        )
        .await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        enroll_result?
    };

    Ok(HttpResponse::Ok()
        .json(crate::crowdsec::models::CrowdSecConsoleEnrollResponse { status: response }))
}

#[get("/crowdsec/decisions")]
async fn crowdsec_decisions(
    cfg: web::Data<Arc<Config>>,
    query: web::Query<CrowdSecDecisionsQuery>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let decisions_result = decisions::list(&query).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        decisions_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[delete("/crowdsec/decisions/{id}")]
async fn delete_crowdsec_decision(
    cfg: web::Data<Arc<Config>>,
    id: web::Path<String>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let delete_result = decisions::delete(&id).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        delete_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/decisions/flush")]
async fn flush_crowdsec_decisions(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecDecisionsFlushRequest>,
) -> Result<HttpResponse> {
    decisions::require_flush_confirmation(request.confirm)?;

    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let flush_result = decisions::flush().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        flush_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/crowdsec/alerts")]
async fn crowdsec_alerts(
    cfg: web::Data<Arc<Config>>,
    query: web::Query<CrowdSecAlertsQuery>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let alerts_result = alerts::list(&query).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        alerts_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/crowdsec/bouncers")]
async fn crowdsec_bouncers(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let bouncers_result = bouncers::list().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        bouncers_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/lapi/central/configure")]
async fn configure_crowdsec_central_lapi(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecCentralLapiConfigureRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let configure_result = lapi::configure_central(&request.listen_uri).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        configure_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/crowdsec/lapi/replication/readiness")]
async fn crowdsec_lapi_replication_readiness(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let response: CrowdSecLapiReplicationReadinessResponse = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let readiness_result = lapi::replication_readiness().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        readiness_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/crowdsec/lapi/machines")]
async fn crowdsec_lapi_machines(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let machines_result = lapi::machines().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        machines_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/lapi/machines/{name}/validate")]
async fn validate_crowdsec_lapi_machine(
    cfg: web::Data<Arc<Config>>,
    name: web::Path<String>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let validate_result = lapi::validate_machine(&name).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        validate_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/lapi/machines/activate")]
async fn activate_crowdsec_remote_machine(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecRemoteMachineActivationRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let activation_result = lapi::activate_remote_machine(
            &request.machine_name,
            request.local_remediation,
            request.backend,
            request.bouncer_api_key.as_deref(),
            Some(&progress),
        )
        .await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        match activation_result {
            Ok(response) => response,
            Err(error) => {
                emit_progress_error(&progress, "CrowdSec machine activation failed");
                return Err(error);
            }
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/lapi/machines/reauthenticate")]
async fn reauthenticate_crowdsec_remote_machine(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecRemoteMachineReauthenticationRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let response = {
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        lapi::reauthenticate_remote_machine(
            &request.machine_name,
            &request.lapi_url,
            Some(&progress),
        )
        .await?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/lapi/machines/resume")]
async fn resume_crowdsec_remote_machine(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecRemoteMachineResumeRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let response = {
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        lapi::resume_remote_machine(
            &request.machine_name,
            request.local_remediation,
            Some(&progress),
        )
        .await?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[delete("/crowdsec/lapi/machines/{name}")]
async fn remove_crowdsec_lapi_machine(
    cfg: web::Data<Arc<Config>>,
    name: web::Path<String>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let remove_result = lapi::remove_machine(&name).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        remove_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/bouncers/register")]
async fn register_crowdsec_bouncer(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecBouncerRegisterRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let register_result = bouncers::register(&request.name).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        register_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[delete("/crowdsec/bouncers/{name}")]
async fn remove_crowdsec_bouncer(
    cfg: web::Data<Arc<Config>>,
    name: web::Path<String>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let remove_result = bouncers::remove(&name).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        remove_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/install")]
async fn install_crowdsec(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecInstallRequest>,
) -> Result<HttpResponse> {
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let response = match request.mode {
            CrowdSecInstallMode::Lapi => {
                let install_result =
                    install::install_with_backend_and_progress(request.backend, Some(&progress))
                        .await;
                match install_result {
                    Ok(response) => HttpResponse::Ok().json(response),
                    Err(error) => {
                        emit_progress_error(&progress, "CrowdSec installation failed");
                        return Err(error);
                    }
                }
            }
            CrowdSecInstallMode::Machine => {
                let install_result = lapi::install_remote_machine(
                    required_machine_install_value(&request.machine_name, "machine_name")?,
                    required_machine_install_value(&request.lapi_url, "lapi_url")?,
                    request.continue_without_lapi_connectivity,
                    Some(&progress),
                )
                .await;
                match install_result {
                    Ok(response) => HttpResponse::Ok().json(response),
                    Err(error) => {
                        emit_progress_error(&progress, "CrowdSec machine installation failed");
                        return Err(error);
                    }
                }
            }
        };

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        response
    };

    Ok(response)
}

fn required_machine_install_value<'a>(value: &'a Option<String>, field: &str) -> Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            crate::errors::FwcError::crowdsec(
                crate::crowdsec::errors::MACHINE_INVALID,
                match field {
                    "machine_name" => "CrowdSec machine name is required",
                    "lapi_url" => "CrowdSec Local API URL is required",
                    _ => "Invalid CrowdSec machine installation request",
                },
            )
        })
}

#[post("/crowdsec/uninstall")]
async fn uninstall_crowdsec(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecUninstallRequest>,
) -> Result<HttpResponse> {
    uninstall::require_confirmation(request.confirm)?;
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;

    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let uninstall_result = uninstall::uninstall_with_progress(Some(&progress)).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        match uninstall_result {
            Ok(response) => response,
            Err(error) => {
                emit_progress_error(&progress, "CrowdSec uninstall failed");
                return Err(error);
            }
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/bouncer/install")]
async fn install_crowdsec_bouncer(
    cfg: web::Data<Arc<Config>>,
    body: web::Bytes,
) -> Result<HttpResponse> {
    let request = bouncer_install_request(&body)?;
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let install_result =
            bouncers::install_with_backend_and_progress(request.backend, Some(&progress)).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        match install_result {
            Ok(response) => response,
            Err(error) => {
                emit_progress_error(&progress, "CrowdSec Firewall Bouncer installation failed");
                return Err(error);
            }
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

fn bouncer_install_request(body: &[u8]) -> Result<CrowdSecBouncerInstallRequest> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(CrowdSecBouncerInstallRequest::default());
    }

    serde_json::from_slice(body).map_err(|_| {
        crate::errors::FwcError::crowdsec(
            crate::crowdsec::errors::BOUNCER_INVALID,
            "Invalid CrowdSec Firewall Bouncer installation request",
        )
    })
}

#[post("/crowdsec/bouncer/uninstall")]
async fn uninstall_crowdsec_bouncer(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecBouncerUninstallRequest>,
) -> Result<HttpResponse> {
    uninstall::require_confirmation(request.confirm)?;
    let progress = CrowdSecProgress::from_request(&cfg, request.ws_id)?;

    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        crate::crowdsec::transitions::address::ensure_idle(cfg.data_dir).await?;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let uninstall_result = bouncers::uninstall_with_progress(Some(&progress)).await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        match uninstall_result {
            Ok(response) => response,
            Err(error) => {
                emit_progress_error(&progress, "CrowdSec Firewall Bouncer uninstall failed");
                return Err(error);
            }
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

fn emit_progress_error(progress: &CrowdSecProgress, message: &str) {
    progress.typed_message(CrowdSecProgressMessageType::Error, message);
}

#[cfg(test)]
mod tests {
    use super::bouncer_install_request;
    use crate::crowdsec::models::CrowdSecFirewallBackend;

    #[test]
    fn bouncer_install_request_defaults_to_iptables_when_empty() {
        let request = bouncer_install_request(b"").unwrap();

        assert_eq!(request.backend, CrowdSecFirewallBackend::Iptables);
    }

    #[test]
    fn bouncer_install_request_rejects_invalid_json() {
        assert!(bouncer_install_request(b"{").is_err());
    }
}
