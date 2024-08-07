// Blackout - Encrypted password/notes and totp manager
// Copyright (C) 2024 James Andrus
// Email: jandrus@citadel.edu

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::fs::File;
use std::io::Read;

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Local};
use directories::ProjectDirs;

struct Project<T: AsRef<str>> {
    qualifier: T,
    org: T,
    app: T,
}

pub enum ProjFiles {
    BackupDir,
    BackupNew,
    Conf,
    Data,
    WordList,
}

const PROJECT: Project<&'static str> = Project {
    qualifier: "io",
    org: "ash",
    app: "blackout",
};

pub const BACKUP_DIR: &str = "backups";
pub const CONF_FILE: &str = "config.toml";
pub const DATA_FILE: &str = "blackout.db";
pub const WL_FILE: &str = "wordlist.txt";
pub const MIN_PASS_SIZE: usize = 10;

pub fn get_time_from_ts(ts: i64) -> Result<String> {
    let dt: DateTime<Local> = match DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.with_timezone(&Local),
        None => bail!("Invalid Timestamp"),
    };
    Ok(dt.format("%Y-%m-%d %H%M").to_string())
}

pub fn get_project() -> Option<ProjectDirs> {
    ProjectDirs::from(PROJECT.qualifier, PROJECT.org, PROJECT.app)
}

pub fn get_project_file(file: ProjFiles) -> Result<String> {
    if let Some(proj) = get_project() {
        match file {
            ProjFiles::BackupDir => {
                return Ok(format!(
                    "{}/{}",
                    proj.data_dir().to_str().unwrap(),
                    BACKUP_DIR
                ));
            }
            ProjFiles::BackupNew => {
                return Ok(format!(
                    "{}/{}/{}.backup.db",
                    proj.data_dir().to_str().unwrap(),
                    BACKUP_DIR,
                    get_timestamp()
                ));
            }
            ProjFiles::Conf => {
                return Ok(format!(
                    "{}/{}",
                    proj.config_dir().to_str().unwrap(),
                    CONF_FILE
                ));
            }
            ProjFiles::Data => {
                return Ok(format!(
                    "{}/{}",
                    proj.data_dir().to_str().unwrap(),
                    DATA_FILE
                ));
            }
            ProjFiles::WordList => {
                return Ok(format!(
                    "{}/{}",
                    proj.config_dir().to_str().unwrap(),
                    WL_FILE
                ));
            }
        }
    }
    Err(anyhow!("Could not get project file"))
}

pub fn get_timestamp() -> i64 {
    Local::now().timestamp()
}

pub fn get_rfc() -> String {
    Local::now().to_rfc2822()
}

pub fn read_file(path: &str) -> Result<String> {
    let mut s = String::new();
    let mut f = File::open(path)?;
    f.read_to_string(&mut s)?;
    Ok(s)
}

pub fn stretch_string(mut s: String, add: Option<u8>) -> String {
    let (cols, _) = term_size::dimensions().unwrap_or((0, 0));
    let space_to_add = cols - s.len();
    if space_to_add > 0 {
        (0..space_to_add).for_each(|_| {
            s.push(' ');
        })
    }
    if let Some(add_space) = add {
        (0..add_space).for_each(|_| {
            s.push(' ');
        })
    }
    s.to_string()
}
