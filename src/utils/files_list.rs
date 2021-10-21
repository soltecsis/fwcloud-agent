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
    if !self.dir_exists() {
      return Err(FwcError::DirNotFound);
    }

    for inx in 0..self.len() {
      let path = self.path(inx);
      if Path::new(&path).is_file() {
        fs::remove_file(path)?;
      }
    }

    Ok(())
  }

  pub fn get_files_in_dir(&mut self) -> Result<()> {
    if !self.dir_exists() {
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

    for inx in 0..self.len() {
      let path = self.path(inx);
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

        csv.push_str(&format!("{},{}\n",self.name(inx),hash));
      }
    }

    Ok(csv)
  }


  pub fn dump(&self, inx: usize) -> Result<Vec<String>> {
    let mut data: Vec<String> = vec![];

    let fr = File::open(self.path(inx))?;
    let reader = BufReader::new(&fr);
    
    for l in reader.lines() {
      let line = l?;
      data.push(line);
    }

    Ok(data)
  }


  pub fn head_remove(&self, inx: usize, max_lines: usize) -> Result<Vec<String>> {
    let mut data: Vec<String> = vec![];

    let path = self.path(inx);
    // If OpenVPN status cache file doesn't exists return empty data.
    if !Path::new(&path).is_file() { 
      return Ok(data)
    }

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

  pub fn path(&self, inx: usize) -> String {
    format!("{}/{}",self.dir(),self.name(inx))
  }

  pub fn chdir(&mut self, new_dir: &str) {
    self.dir = String::from(new_dir);
  }

  pub fn rename(&mut self, inx: usize, new_name: &str) {
    self.files[inx] = String::from(new_name);
  }

  pub fn dir(&self) -> String {
    String::from(&self.dir)
  }

  pub fn dir_exists(&self) -> bool {
    if Path::new(&self.dir).is_dir() { true } else { false }
  }

  pub fn name(&self, inx: usize) -> String {
    String::from(&self.files[inx])
  }

  pub fn len(&self) -> usize {
    self.files.len()
  }
}


#[cfg(test)]
mod tests {
  use super::*;
  use rand::Rng;
  use uuid::Uuid;
  use sha2::Sha256;
  use std::fs::OpenOptions;

  fn files_list_factory(n: usize) -> FilesList {
    // Directory with a random name.
    let dir = format!("./tests/playground/tmp/{}",Uuid::new_v4().to_string());
    let mut fl = FilesList {
      dir,
      files: vec![]
    };

    for _ in 0..n {
      fl.files.push(Uuid::new_v4().to_string());
    }

    fl
  }

  fn create_files(fl: &FilesList) -> Result<()> {
    fs::create_dir(&fl.dir())?;

    for inx in 0..fl.len() {
      let fw = File::create(fl.path(inx))?;
      let mut writer = BufWriter::new(&fw);
      writeln!(writer, "{}_{}\n", Uuid::new_v4().to_string(),Uuid::new_v4().to_string())?;
    }

    // Verify that the files have been created.
    for inx in 0..fl.len() {
      if !Path::new(&fl.path(inx)).is_file() {
        return Err(FwcError::Internal("File not created"));
      }
    }

    Ok(())
  }

  fn sha256_cvs_string(fl: &mut FilesList) -> Result<String> {
    let mut cvs = String::from("file,sha256\n");
    for inx in 0..fl.len() {
      let mut file = File::open(&fl.path(inx))?;
      let mut sha256 = Sha256::new();
      io::copy(&mut file, &mut sha256)?;
      let line = format!("{},{}\n",&fl.name(inx),hex::encode(sha256.finalize()));
      cvs.push_str(&line);
    }

    Ok(cvs)
  }


  #[test]
  fn len_for_zero_files() {
    let fl = files_list_factory(0);
    assert_eq!(fl.len(),0);
  }


  #[test]
  fn len_for_some_files() { 
    let n = rand::thread_rng().gen_range(1..6);
    let fl = files_list_factory(n);
    assert_eq!(fl.len(),n);
  }


  #[test]
  fn right_file_name() { 
    let fl = files_list_factory(5);
    let inx = rand::thread_rng().gen_range(0..5);
    assert_eq!(fl.name(inx),fl.files[inx]);
  }


  #[test]
  fn directory_exists() { 
    let fl = files_list_factory(0);
    fs::create_dir(&fl.dir()).unwrap();
    assert!(fl.dir_exists());
    fs::remove_dir(fl.dir()).unwrap();
  }


  #[test]
  fn directory_not_exists() { 
    let fl = files_list_factory(0);
    assert!(!fl.dir_exists());
  }


  #[test]
  fn get_directory() { 
    let fl = files_list_factory(0);
    assert_eq!(fl.dir(),fl.dir);
  }


  #[test]
  fn rename_file() { 
    let mut fl = files_list_factory(5);
    let inx = rand::thread_rng().gen_range(0..5);
    let new_file_name = "new_file_name";

    fl.rename(inx, new_file_name);
    assert_eq!(fl.files[inx],new_file_name);
  }


  #[test]
  fn change_directory() { 
    let mut fl = files_list_factory(0);
    let new_directory_name = "./new_directory_name";

    fl.chdir(new_directory_name);
    assert_eq!(fl.dir,new_directory_name);
  }


  #[test]
  fn remove_all_files() -> Result<()> { 
    let n = rand::thread_rng().gen_range(1..6);
    let fl = files_list_factory(n);

    create_files(&fl)?;

    // Check that the files have been removed from the directory.
    fl.remove()?;
    for inx in 0..fl.len() {
      if Path::new(&fl.path(inx)).is_file() {
        fs::remove_dir(fl.dir())?;
        return Err(FwcError::Internal("File not removed"));
      }
    }

    fs::remove_dir(fl.dir())?;
    Ok(())
  }


  #[test]
  fn remove_returns_error_if_dir_not_exists() {
    let fl = files_list_factory(0);

    match fl.remove() {
      Err(e) => { match e {
        FwcError::DirNotFound => assert!(true),
        _ => return assert!(false)
      }}, 
      Ok(_) => panic!("Error expected")
    }
  }


  #[test]
  fn get_files_in_dir_gets_all_files() -> Result<()> { 
    let n = rand::thread_rng().gen_range(1..6);
    let mut fl1 = files_list_factory(n);

    create_files(&fl1)?;

    let mut fl2 = files_list_factory(0);
    fl2.chdir(&fl1.dir());
    fl2.get_files_in_dir()?;
    fl1.remove()?;
    fs::remove_dir(&fl1.dir())?;

    // Check that all directory files have been read.
    if fl1.files.sort() == fl2.files.sort() {
      Ok(())
    } else {
      Err(FwcError::Internal("Getting files"))
    }
  }


  #[test]
  fn get_files_in_dir_returns_error_if_dir_not_exists() {
    let mut fl = files_list_factory(0);

    match fl.get_files_in_dir() {
      Err(e) => { match e {
        FwcError::DirNotFound => assert!(true),
        _ => return assert!(false)
      }}, 
      Ok(_) => panic!("Error expected")
    }
  }


  #[test]
  fn sha256_gives_empty_result_if_dir_is_empty() {
    let fl = files_list_factory(0);

    fs::create_dir(&fl.dir()).unwrap();
    assert_eq!(fl.sha256(false).unwrap(),String::from("file,sha256\n"));
    fs::remove_dir(fl.dir()).unwrap();
  }


  #[test]
  fn sha256_gives_empty_result_if_dir_not_exists() {
    let fl = files_list_factory(0);
    assert_eq!(fl.sha256(false).unwrap(),String::from("file,sha256\n"));
  }


  #[test]
  fn sha256_files_without_comments() -> Result<()> {
    let mut fl = files_list_factory(5);

    create_files(&fl)?;
    let result = fl.sha256(false)?;
    let result_ignore_comments = fl.sha256(true)?;
    let compare = sha256_cvs_string(&mut fl)?;
    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(result,compare);
    // No comments in files, then the result must be the same.
    assert_eq!(result_ignore_comments,compare);

    Ok(())
  }


  #[test]
  fn sha256_files_with_comments() -> Result<()> {
    let mut fl = files_list_factory(5);

    create_files(&fl)?;

    // Add comments to one file.
    let mut file = OpenOptions::new()
      .write(true)
      .append(true)
      .open(fl.path(3))
      .unwrap();
    writeln!(file, "# First comment line!")?;
    writeln!(file, "# Second comment line!")?;

    let result = fl.sha256(false)?;
    let result_ignore_comments = fl.sha256(true)?;
    let compare = sha256_cvs_string(&mut fl)?;
    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(result,compare);
    // We have comments in one file, then the result when we ignore the comments must be different.
    assert_ne!(result_ignore_comments,compare);

    Ok(())
  }
}
