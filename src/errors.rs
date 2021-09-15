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

//use std::fmt::{self, Debug};

use actix_web::{HttpResponse, ResponseError, http::{StatusCode, header}};
use thiserror::Error;
use log::error;

pub type Result<T> = std::result::Result<T, FwcError>;

#[derive(Error, Debug)]
pub enum FwcError {
  #[error("API key not found")]
  ApiKeyNotFound,

  #[error("Invalid API key")]
  ApiKeyNotValid,

  #[error("Authorization error, access from your IP is not allowed")]
  NotAllowedIP,

  #[error("Not allowed parameter in request")]
  NotAllowedParameter,

  #[error("Directory not found")]
  DirNotFound,

  #[error("At least one file must be included in the request")]
  AtLeastOneFile,

  #[error("{0}")]
  Internal(&'static str),

  #[error(transparent)]
  Validation(#[from] validator::ValidationErrors),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  BlockingError(#[from] actix_web::error::BlockingError<std::io::Error>)
}

impl ResponseError for FwcError {
    fn status_code(&self) -> StatusCode {
      match self {
        FwcError::NotAllowedParameter | FwcError::AtLeastOneFile | FwcError::Validation(_) 
          => StatusCode::BAD_REQUEST,
        FwcError::ApiKeyNotValid | FwcError::ApiKeyNotFound | &FwcError::NotAllowedIP
          =>  StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR
      }
    }

    fn error_response(&self) -> HttpResponse {
      let mut resp = HttpResponse::new(self.status_code());
      resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
      );
      
      error!("{}",self);
      resp.set_body(actix_web::dev::Body::from(format!("{{\"message\":\"{}\"}}",self)))
    }
}
