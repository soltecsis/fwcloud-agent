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

use serde::Deserialize;
use std::fs;
use std::path::Path;

use crate::errors::{FwcError, Result};

#[derive(Deserialize)]
pub struct FilesList {
  dir: String,
  files: Vec<String>
}

impl FilesList {
  pub fn remove(&self) -> Result<()> {
    if !Path::new(&self.dir).is_dir() {
      return Err(FwcError::DirNotFound);
    }

    for file in self.files.iter() {
      let path = format!("{}/{}",self.dir,file);
      if Path::new(&path).is_file() {
        fs::remove_file(path)?;
      }
    }

    Ok(())
  } 
}