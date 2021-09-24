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
use subprocess::{Exec, Redirection};
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
  perms_u32: u32,
  max_files: u32,
  max_file_size: usize,
  expected_files: u32,
  n_files: u32
}

struct FileData {
  src_path: String,
  src_name: String,
  dst_path: String,
  dst_name: String,
  size: usize
}

impl HttpFiles {
  pub fn new(tmp_dir: String) -> Self {
    HttpFiles {
      tmp_dir,
      dst_dir: String::from(""),
      files: Vec::new(),
      perms: String::from("640"),
      perms_u32: 420,
      max_files: 1000,
      max_file_size: 10_485_760, // Ten megabytes.
      expected_files: 0,
      n_files: 0
    }
  } 

  pub async fn files_upload(&mut self, payload: Multipart) -> Result<()> {
    self.extract_multipart_data(payload).await?;
    self.check_data()?;
    self.move_tmp_files()?;
    
    Ok(())
  }

  pub async fn fwcloud_script(&mut self, payload: Multipart) -> Result<String> {
    self.expected_files = 1;
    self.extract_multipart_data(payload).await?;
    self.check_data()?;

    if self.files[0].dst_name != "fwcloud.sh" {
      return Err(FwcError::NotExpectedFileName)
    }

    self.move_tmp_files()?;

    // Now run the FWCloud script with the install option.
    let output = self.run("sh",&[self.files[0].dst_path.clone(), "install".to_string()])?;
    
    Ok(output)
  }

  async fn extract_multipart_data(&mut self, mut payload: Multipart) -> Result<()> {
    // iterate over multipart stream
    while let Ok(Some(mut field)) = payload.try_next().await {
      let content_type = field.content_disposition().unwrap();
      
      let filename = sanitize_filename::sanitize(content_type.get_filename().unwrap_or("").to_string());
      if filename.len() == 0 {
        let name = content_type.get_name().unwrap_or("").to_string();
        self.extract_field_data(field, name).await?;
        continue;
      }

      // Parameter for destination dir (dst_dir) must go before any file contents in the
      // multipart stream.
      if self.dst_dir.len() == 0 {
        return Err(FwcError::DstDirFirst);
      }

      // Apply controls over the amount of files before getting the next file.
      self.n_files += 1;
      if self.max_files > 0 && self.n_files > self.max_files {
        return Err(FwcError::TooManyFiles);
      }
      if self.expected_files > 0 && self.n_files > self.expected_files {
        return Err(FwcError::MoreFilesThanExpected);
      }
      
      let random_file_name = Uuid::new_v4();
      let mut file_data = FileData {
        src_path: format!("{}/{}.tmp", self.tmp_dir, random_file_name),
        src_name: format!("{}.tmp", random_file_name),
        dst_path: format!("{}/{}", self.dst_dir, filename),
        dst_name: filename,
        size: 0
      };

      // File::create is blocking operation, use threadpool
      let file_path = file_data.src_path.clone();
      let mut f = web::block(|| std::fs::File::create(file_path))
        .await
        .unwrap();

      // Field in turn is stream of *Bytes* object
      while let Some(chunk) = field.next().await {
        let data = chunk.unwrap();
        
        // File size control.
        file_data.size += data.len();
        if self.max_file_size >0 && file_data.size > self.max_file_size {
          return Err(FwcError::TooBigFile);
        }

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

    // Verify that destination directory exists.
    // The parameter dst_dir must go before any file into the multipart stream. 
    // If the destination directory doesn't exists we will response with error before processing the files
    // data.
    if name == "dst_dir" {
      if !Path::new(&self.dst_dir).is_dir() {
        return Err(FwcError::DirNotFound);
      }
    }

    Ok(())
  }

  fn move_tmp_files(&mut self) -> Result<()> {
    for file_data in self.files.iter() {
      fs::copy(&file_data.src_path,&file_data.dst_path)?;
      fs::remove_file(&file_data.src_path)?;

      let mut perms = fs::metadata(&file_data.dst_path)?.permissions();
      perms.set_mode(self.perms_u32);
      fs::set_permissions(&file_data.dst_path, perms)?;
    }

    Ok(())
  }

  fn check_data(&mut self) -> Result<()> {
    // Validate data using the Validator crate and the marco annotations over struct fields.
    self.validate()?;
    
    // Destination directory parameter is mandatory.
    if self.dst_dir.len() < 1 {
      return Err(FwcError::Internal("Destination directory parameter not found in multipart/form-data stream"));
    }

    if self.files.len() < 1 {
      return Err(FwcError::AtLeastOneFile);
    }

    if self.n_files < self.expected_files {
      return Err(FwcError::LessFilesThanExpected);
    }

    self.perms_to_u32();

    Ok(())
  }

  fn perms_to_u32(&mut self) {
    let d0 = (self.perms.as_bytes()[0] as u32) - 48;
    let d1 = (self.perms.as_bytes()[1] as u32) - 48;
    let d2 = (self.perms.as_bytes()[2] as u32) - 48;

    self.perms_u32 = (d0 * 64) + (d1 * 8) + d2;
  }
  
  fn run(&mut self, cmd: &str, args: &[String]) -> Result<String>{
    Ok(Exec::cmd(cmd)
        .args(args)
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()?
        .stdout_str()
    )
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
    use super::*;

    #[test]
    fn unix_permissions_to_u32() {
      let mut item = HttpFiles::new("".to_string());
      
      item.perms = String::from("777"); item.perms_to_u32();
      assert_eq!(item.perms_u32, 511);

      item.perms = String::from("644"); item.perms_to_u32();
      assert_eq!(item.perms_u32, 420);

      item.perms = String::from("650"); item.perms_to_u32();
      assert_eq!(item.perms_u32, 424);
    }
}
