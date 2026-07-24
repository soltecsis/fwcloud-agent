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

use actix_web::{get, post, web, HttpResponse};
use log::debug;

use crate::{
    config::Config,
    crowdsec::{
        bouncer, collections, console, install,
        models::{
            CrowdSecBouncerInstallRequest, CrowdSecBouncerUninstallRequest,
            CrowdSecCollectionInstallRequest, CrowdSecCollectionRemoveRequest,
            CrowdSecCollectionUpdateRequest, CrowdSecCollectionsQuery,
            CrowdSecConsoleDisableRequest, CrowdSecConsoleEnrollRequest, CrowdSecInstallRequest,
            CrowdSecUninstallRequest,
        },
        status, uninstall,
    },
    errors::Result,
};

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

#[post("/crowdsec/console/disable")]
async fn disable_crowdsec_console(
    _request: web::Json<CrowdSecConsoleDisableRequest>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "code": "CROWDSEC_CONSOLE_NOT_IMPLEMENTED",
        "message": "CrowdSec Console disable is not implemented yet"
    })))
}

#[post("/crowdsec/install")]
async fn install_crowdsec(
    cfg: web::Data<Arc<Config>>,
    _request: web::Json<CrowdSecInstallRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let install_result = install::install().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        install_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/uninstall")]
async fn uninstall_crowdsec(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecUninstallRequest>,
) -> Result<HttpResponse> {
    uninstall::require_confirmation(request.confirm)?;

    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let uninstall_result = uninstall::uninstall().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        uninstall_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/bouncer/install")]
async fn install_crowdsec_bouncer(
    cfg: web::Data<Arc<Config>>,
    _request: web::Json<CrowdSecBouncerInstallRequest>,
) -> Result<HttpResponse> {
    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let install_result = bouncer::install().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        install_result?
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/crowdsec/bouncer/uninstall")]
async fn uninstall_crowdsec_bouncer(
    cfg: web::Data<Arc<Config>>,
    request: web::Json<CrowdSecBouncerUninstallRequest>,
) -> Result<HttpResponse> {
    uninstall::require_confirmation(request.confirm)?;

    let response = {
        debug!("Locking CrowdSec mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.crowdsec);
        let _mutex_data = mutex.lock().await;
        debug!("CrowdSec mutex locked (thread id: {})", thread_id::get());

        let uninstall_result = bouncer::uninstall().await;

        debug!("Releasing CrowdSec mutex (thread id: {})", thread_id::get());
        uninstall_result?
    };

    Ok(HttpResponse::Ok().json(response))
}
