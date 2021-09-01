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

use std::io::Write;

use actix_multipart::{Multipart, Field};
use actix_web::web;
use futures::{StreamExt, TryStreamExt};
use uuid::Uuid;
use std::fs;
use std::path::Path;

use crate::errors::FwcError;

pub struct HttpFiles {
  tmp_dir: String,
  dst_dir: String,
  files: Vec<FileData>
}

struct FileData {
  src_name: String,
  dst_name: String
}

impl HttpFiles {
  pub fn new(tmp_dir: String) -> Self {
    HttpFiles {
      tmp_dir,
      dst_dir: "".to_string(),
      files: Vec::new()
    }
  } 

  pub async fn process(&mut self, payload: Multipart) -> Result<(), FwcError> {
    self.extract_multipart_data(payload).await?;
    self.validate()?;
    self.move_tmp_files()?;
    
    Ok(())
  }

  async fn extract_dst_dir(&mut self, mut field: Field, name: String) -> Result<(), FwcError> {
    // We only accept one NO file parameter in the multipart stream and it must be the destination directory.
    if name != "dst_dir" {
      //return Err(HttpResponse::BadRequest().body("ERROR: Not accepted parameter.").into());
      return Err(FwcError::NotAllowedParameter);
    }

    // Field in turn is stream of *Bytes* object
    while let Some(chunk) = field.next().await {
      let data = chunk.unwrap();
      for byte in data {
        self.dst_dir.push(byte as char);
      }
    }

    Ok(())
  }

  async fn extract_multipart_data(&mut self, mut payload: Multipart) -> Result<(), FwcError> {
    // iterate over multipart stream
    while let Ok(Some(mut field)) = payload.try_next().await {
      let content_type = field.content_disposition().unwrap();
      
      let filename = content_type.get_filename().unwrap_or("").to_string();
      if filename.len() == 0 {
        let name = content_type.get_name().unwrap_or("").to_string();
        self.extract_dst_dir(field, name).await?;
        continue;
      }
      
      let file_data = FileData {
        src_name: format!("{}.tmp", Uuid::new_v4()),
        dst_name: filename
      };
      let filepath = format!("{}/{}", self.tmp_dir, sanitize_filename::sanitize(&file_data.src_name));

      // File::create is blocking operation, use threadpool
      let mut f = web::block(|| std::fs::File::create(filepath))
        .await
        .unwrap();

      // Field in turn is stream of *Bytes* object
      while let Some(chunk) = field.next().await {
        let data = chunk.unwrap();
        // filesystem operations are blocking, we have to use threadpool
        f = web::block(move || f.write_all(&data).map(|_| f)).await?;
      }

      self.files.push(file_data);
    }

    Ok(())
  }

  fn move_tmp_files(&mut self) -> Result<(), FwcError> {
    for file_data in self.files.iter() {
      let src = format!("{}/{}",self.tmp_dir,file_data.src_name);
      let dst = format!("{}/{}",self.dst_dir,file_data.dst_name);

      fs::copy(&src,&dst)?;
      fs::remove_file(&src)?;
    }

    Ok(())
  }

  fn validate(&self) -> Result<(), FwcError> {
    // Destination directory parameter is mandatory.
    if self.dst_dir.len() < 1 {
      return Err(FwcError::Custom("Destination directory parameter not found in multipart/form-data stream"));
    }

    if !Path::new(&self.dst_dir).is_dir() {
      return Err(FwcError::DirNotFound);
    }

    if self.files.len() < 1 {
      return Err(FwcError::AtLeastOneFile);
    }

    Ok(())
  }
}

// Make sure that temporary files are removed after the HttpFiles object instance goes out of scope.
impl Drop for HttpFiles {
  fn drop(&mut self) {
    for file_data in self.files.iter() {
      let src = format!("{}/{}",self.tmp_dir,file_data.src_name);

      // Ignore the Result enum returned by the remove_file method.
      let _ = fs::remove_file(&src);
    }
  }
}
