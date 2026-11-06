/*
    Copyright 2025 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{prelude::*, BufReader, BufWriter};
use std::path::Path;

use crate::errors::{FwcError, Result};

#[derive(Deserialize)]
pub struct FilesList {
    dir: String,
    files: Vec<String>,
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
                self.files.push(String::from(
                    entry.path().file_name().unwrap().to_str().unwrap(),
                ));
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
                        if !line.is_empty() && line.starts_with('#') {
                            continue;
                        }
                        sha256.update(line + "\n");
                    }
                } else {
                    let mut buffer = [0_u8; 8192];
                    loop {
                        let read = file_stream.read(&mut buffer)?;
                        if read == 0 {
                            break;
                        }
                        sha256.update(&buffer[..read]);
                    }
                }

                let hast = hex::encode(sha256.finalize());
                let line = format!("{},{}\n", self.name(inx), hast);
                csv.push_str(&line);
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

        // If file doesn't exists return empty data.
        if !Path::new(&path).is_file() {
            return Ok(data);
        }

        let path_tmp = format!("{path}.tmp");

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
                    writeln!(writer, "{line}")?;
                }
            }
        }

        fs::copy(&path_tmp, &path)?;
        fs::remove_file(&path_tmp)?;

        Ok(data)
    }

    pub fn path(&self, inx: usize) -> String {
        format!("{}/{}", self.dir(), self.name(inx))
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
        Path::new(&self.dir).is_dir()
    }

    pub fn name(&self, inx: usize) -> String {
        String::from(&self.files[inx])
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }
}

#[cfg(test)]
#[path = "files_list_tests.rs"]
mod tests;
