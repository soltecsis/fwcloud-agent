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
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, prelude::*};
use std::path::Path;
use sha2::{Sha256, Digest};

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

  pub fn get_files_in_dir(&mut self) -> Result<()> {
    if !Path::new(&self.dir).is_dir() {
      return Err(FwcError::DirNotFound);
    }

    for entry in fs::read_dir(&self.dir)? {
      let entry = entry?;
      if entry.path().is_file() {
        self.files.push(String::from(entry.path().file_name().unwrap().to_str().unwrap()));
      }
    }

    Ok(())
  }
  
  pub fn sha256(&self, ignore_comments: bool) -> Result<String> {
    let mut csv = String::from("file,sha256\n");

    for file in self.files.iter() {
      let path = format!("{}/{}",self.dir,file);
      if Path::new(&path).is_file() {
        
        let mut file_stream = File::open(&path)?;
        let mut sha256 = Sha256::new();

        if ignore_comments {
          let reader = BufReader::new(file_stream);

          for line in reader.lines() {
            let line = line?;
            if line.len() > 0 && line.chars().nth(0).unwrap() == '#' {
              continue;
            }
            sha256.update(line+"\n");
          }
        } else {
          io::copy(&mut file_stream, &mut sha256)?;
        }

        let hash = hex::encode(sha256.finalize().as_slice());

        csv.push_str(&format!("{},{}\n",file,hash));
      }
    }

    Ok(csv)
  }


  pub fn head_remove(&self, inx: usize, max_lines: usize) -> Result<Vec<String>> {
    let mut data: Vec<String> = vec![];

    let path = format!("{}/{}",self.dir,self.files[inx]);
    let path_tmp = format!("{}.tmp",path);

    {
      let fr = File::open(&path)?;
      let reader = BufReader::new(&fr);
      
      let fw = File::create(&path_tmp)?;
      let mut writer = BufWriter::new(&fw);

      for (n, l) in reader.lines().enumerate() {
        let line = l?;

        if n < max_lines {
          data.push(line);
        } else {
          // If we arrive here we have more lines in the file that must be preserved.
          writeln!(writer, "{}", line)?;
        }
      }
    }

    fs::copy(&path_tmp,&path)?;
    fs::remove_file(&path_tmp)?;

    Ok(data)
  }


  pub fn chdir(&mut self, new_dir: &str) {
    self.dir = String::from(new_dir);
  }


  pub fn rename(&mut self, inx: usize, new_name: &str) {
    self.files[inx] = String::from(new_name);
  }

  pub fn dir(&mut self) -> String {
    String::from(&self.dir)
  }

  pub fn name(&mut self, inx: usize) -> String {
    String::from(&self.files[inx])
  }

  pub fn len(&self) -> usize {
    self.files.len()
  }
}