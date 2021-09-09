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
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error};
use futures::future::{ok, Ready};
use futures::Future;

use crate::errors::FwcError;
use crate::config::Config;

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct Authorize;

// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S> for Authorize
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
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

impl<S, B> Service for AuthorizeMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let cfg: &Config = req.app_data().unwrap();
        let api_key: String; 

        // (1) Verify that the supplied API key is correct.
        match req.headers().get("X-API-Key") {
            Some(value) => api_key = String::from(value.to_str().unwrap()),
            None => return Box::pin(async { Err(Error::from(FwcError::ApiKeyNotFound)) })
        }

        if cfg.api_key != api_key {
            return Box::pin(async { Err(Error::from(FwcError::ApiKeyNotValid)) });
        }

        // (2) Now check that the peer IP is allowed.
        // If allowed_ips vector is empty we are allowing connections form any IP.
        if cfg.allowed_ips.len() > 1 { 
            let mut found = false;

            let remote_ip = match req.connection_info().remote_addr() {
                Some(data) => String::from(data),
                None => return Box::pin(async { Err(Error::from(FwcError::Custom("Allowed IPs list not empty and was not possible to get the remote IP"))) })
            };

            for ip in cfg.allowed_ips.iter() {
                if *ip == remote_ip {
                    found = true;
                    break;
                }
            }
            if ! found {
                return Box::pin(async { Err(Error::from(FwcError::NotAllowedIP)) });
            }
        }


        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}