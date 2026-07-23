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
        bouncer, install,
        models::{
            CrowdSecBouncerInstallRequest, CrowdSecBouncerUninstallRequest, CrowdSecInstallRequest,
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
