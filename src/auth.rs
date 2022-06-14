/*
    Copyright 2021 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, web};
use futures::future::{ok, Ready};
use futures::Future;

use crate::errors::FwcError;
use crate::config::Config;


// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct Authorize;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for Authorize
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    //type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthorizeMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthorizeMiddleware { service })
    }
}

pub struct AuthorizeMiddleware<S> {
    service: S,
}

macro_rules! err {
    ($x: expr) => { Box::pin(async { Err(Error::from($x)) }) };
}

impl<S, B> Service<ServiceRequest> for AuthorizeMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    //type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let api_key: String; 

        let cfg: &web::Data<Arc<Config>> = match req.app_data() {
            Some(val) => val,
            None => return err!(FwcError::Internal("Error accessing configuration from authorization middleware"))
        };

        // (1) Verify that the supplied API key is correct.
        match req.headers().get("X-API-Key") {
            Some(value) => api_key = String::from(value.to_str().unwrap()),
            None => return err!(FwcError::ApiKeyNotFound)
        }

        if cfg.api_key != api_key {
            return err!(FwcError::ApiKeyNotValid);
        }

        // (2) Now check that the peer IP is allowed.
        // If allowed_ips vector is empty we are allowing connections form any IP.
        if cfg.allowed_ips.len() > 0 { 
            let mut found = false;

            let remote_ip = match req.connection_info().peer_addr() {
                Some(data) => {
                        let ip_and_port: Vec<&str> = data.split(":").collect(); 
                        String::from(ip_and_port[0])
                    },
                None => return err!(FwcError::Internal("Allowed IPs list not empty and was not possible to get the remote IP"))
            };

            for ip in cfg.allowed_ips.iter() {
                if *ip == remote_ip {
                    found = true;
                    break;
                }
            }
            if ! found {
                return err!(FwcError::NotAllowedIP);
            }
        }


        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}