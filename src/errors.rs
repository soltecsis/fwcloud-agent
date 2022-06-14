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

use actix_web::{HttpResponse, ResponseError, http::{StatusCode, header}, body::BoxBody};
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

  #[error("Parameter dst_dir must come before any file in the multipart stream")]
  DstDirFirst,

  #[error("At least one file must be included in the request")]
  AtLeastOneFile,

  #[error("Too big file")]
  TooBigFile,

  #[error("Too many files")]
  TooManyFiles,

  #[error("Less files than expected")]
  LessFilesThanExpected,

  #[error("More files than expected")]
  MoreFilesThanExpected,

  #[error("File name was not the expected one")]
  NotExpectedFileName,

  #[error("Only one file expected in request")]
  OnlyOneFileExpected,

  #[error("{0}")]
  Internal(&'static str),

  #[error(transparent)]
  Validation(#[from] validator::ValidationErrors),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  BlockingError(#[from] actix_web::error::BlockingError),

  #[error(transparent)]
  PopenError(#[from] subprocess::PopenError),

  #[error(transparent)]
  SendError(#[from] std::sync::mpsc::SendError<u8>)
}

impl ResponseError for FwcError {
    fn status_code(&self) -> StatusCode {
      match self {
        FwcError::NotAllowedParameter | FwcError::AtLeastOneFile | FwcError::Validation(_) |
        FwcError::TooBigFile | FwcError::TooManyFiles | FwcError::LessFilesThanExpected | 
        FwcError::MoreFilesThanExpected | FwcError::NotExpectedFileName | FwcError::DstDirFirst
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
      resp.set_body(BoxBody::new(format!("{{\"message\":\"{}\"}}",self).to_string()))
    }
}
