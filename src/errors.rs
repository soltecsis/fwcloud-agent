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

use std::{fmt::{self, Debug}, io};

use actix_web::{HttpResponse, ResponseError, error::BlockingError, http::{StatusCode, header}};
use thiserror::Error;
use serde::{Serialize};
use validator::ValidationErrors;

#[derive(Error, Debug, Serialize)]
pub enum FwcError {
  #[error("Not allowed parameter in request")]
  NotAllowedParameter,

  #[error("Directory not found")]
  DirNotFound,

  #[error("At least one file must be included in the request")]
  AtLeastOneFile,

  #[error("`{0}`")]
  Custom(&'static str),
 
  #[error("`{0}`")]
  StdErr(String),

  #[error("`VALIDATION ERROR: {0}`")]
  Validation(String)
}

impl ResponseError for FwcError {
    fn status_code(&self) -> StatusCode {
      match self {
        FwcError::NotAllowedParameter => StatusCode::BAD_REQUEST,
        FwcError::AtLeastOneFile => StatusCode::BAD_REQUEST,
        FwcError::Validation(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR
      }
    }

    fn error_response(&self) -> HttpResponse {
      let mut resp = HttpResponse::new(self.status_code());
      resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
      );
      
      resp.set_body(actix_web::dev::Body::from(format!("{{\"msg\":\"{}\"}}",self)))
    }
}

impl From<io::Error> for FwcError {
  fn from(error: io::Error) -> Self {
    FwcError::StdErr(error.to_string())
  }
}

impl<E: fmt::Debug> From<BlockingError<E>> for FwcError {
  fn from(_: BlockingError<E>) -> Self 
    where
      E: fmt::Debug,
  {  
    FwcError::Custom("Blocking error")
  }
}

impl From<ValidationErrors> for FwcError {
  fn from(error: ValidationErrors) -> Self {
    FwcError::Validation(error.to_string())
  }
}
