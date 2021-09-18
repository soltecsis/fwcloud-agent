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

use std::{io::Write, os::unix::prelude::PermissionsExt};

use actix_multipart::{Multipart, Field};
use actix_web::web;
use futures::{StreamExt, TryStreamExt};
use uuid::Uuid;
use std::fs;
use std::path::Path;
use validator::Validate;

use crate::errors::{FwcError, Result};

#[derive(Validate)]
pub struct HttpFiles {
  tmp_dir: String,
  dst_dir: String,
  files: Vec<FileData>,
  #[validate(regex(path = "crate::utils::myregex::FILE_PERMISSIONS", message = "Invalid file permissions"))]
  perms: String,
  perms_u32: u32
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
      files: Vec::new(),
      perms: "640".to_string(),
      perms_u32: 420
    }
  } 

  pub async fn process(&mut self, payload: Multipart) -> Result<()> {
    self.extract_multipart_data(payload).await?;
    self.check_data()?;
    self.move_tmp_files()?;
    
    Ok(())
  }

  async fn extract_multipart_data(&mut self, mut payload: Multipart) -> Result<()> {
    // iterate over multipart stream
    while let Ok(Some(mut field)) = payload.try_next().await {
      let content_type = field.content_disposition().unwrap();
      
      let filename = content_type.get_filename().unwrap_or("").to_string();
      if filename.len() == 0 {
        let name = content_type.get_name().unwrap_or("").to_string();
        self.extract_field_data(field, name).await?;
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

  async fn extract_field_data(&mut self, mut field: Field, name: String) -> Result<()> {
    // We only accept these NO file parameter in the multipart stream and it must be the destination directory.
    let buf: &mut String;
    if name == "dst_dir" {
      buf = &mut self.dst_dir;
    } else if name == "perms" {
      self.perms.clear();
      buf = &mut self.perms;
    } else {
      return Err(FwcError::NotAllowedParameter);
    }

    // Field in turn is stream of *Bytes* object
    while let Some(chunk) = field.next().await {
      let data = chunk.unwrap();
      for byte in data {
        buf.push(byte as char);
      }
    }

    Ok(())
  }

  fn move_tmp_files(&mut self) -> Result<()> {
    for file_data in self.files.iter() {
      let src = format!("{}/{}",self.tmp_dir,file_data.src_name);
      let dst = format!("{}/{}",self.dst_dir,file_data.dst_name);

      fs::copy(&src,&dst)?;
      fs::remove_file(&src)?;

      let mut perms = fs::metadata(&dst)?.permissions();
      perms.set_mode(self.perms_u32);
      fs::set_permissions(&dst, perms)?;
    }

    Ok(())
  }

  fn check_data(&mut self) -> Result<()> {
    // Validate data using the Validator crate and the marco annotations over struct fields.
    self.validate()?;
    
    self.perms_to_u32();

    // Destination directory parameter is mandatory.
    if self.dst_dir.len() < 1 {
      return Err(FwcError::Internal("Destination directory parameter not found in multipart/form-data stream"));
    }

    if !Path::new(&self.dst_dir).is_dir() {
      return Err(FwcError::DirNotFound);
    }

    if self.files.len() < 1 {
      return Err(FwcError::AtLeastOneFile);
    }

    Ok(())
  }

  fn perms_to_u32(&mut self) {
    let d0 = (self.perms.as_bytes()[0] as u32) - 48;
    let d1 = (self.perms.as_bytes()[1] as u32) - 48;
    let d2 = (self.perms.as_bytes()[2] as u32) - 48;

    self.perms_u32 = (d0 * 64) + (d1 * 8) + d2;
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


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
