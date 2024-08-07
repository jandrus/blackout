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

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, ensure, Result};

use crate::{conf, ui};

#[derive(Clone)]
pub struct Backup {
    pub timestamp: i64,
    pub file_path: String,
    pub hash: String,
}

pub fn restore_backup(conf: &conf::BlackoutConfig) -> Result<()> {
    let current_db_file = lib::get_project_file(lib::ProjFiles::Data)?;
    let current_hash = hash_file(&current_db_file)?;
    let mut backups: Vec<Backup> = get_backups()?
        .into_iter()
        .filter(|b| b.hash != current_hash)
        .collect();
    if backups.is_empty() {
        ui::fmt_print(
            "No backups avaiable or current blackout matches the only available backup",
            ui::ContentType::Info,
            conf,
        );
        return Ok(());
    }
    backups.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let mut backup_strs: Vec<String> = backups
        .iter()
        .map(|b| {
            format!(
                "{} -> {}",
                lib::get_time_from_ts(b.timestamp).unwrap(),
                b.hash
            )
        })
        .collect();
    backup_strs.push("Cancel".to_string());
    let backup_idx =
        ui::get_selection_from_user("Select backup to restore", true, &backup_strs, conf.color)?;
    if backup_idx == backups.len() {
        return Ok(());
    }
    let backup = backups[backup_idx].clone();
    let backups = get_backups()?;
    if !backups.iter().any(|b| b.hash == current_hash)
        && ui::confirm_with_user("Create backup of current blackout", true, conf.color)?
    {
        create_backup(conf)?;
    }
    fs::remove_file(&current_db_file)?;
    fs::copy(backup.file_path, current_db_file)?;
    ui::fmt_print("Backup restored", ui::ContentType::Success, conf);
    Ok(())
}

pub fn create_backup(conf: &conf::BlackoutConfig) -> Result<()> {
    let backups = get_backups()?;
    let current_db_file = lib::get_project_file(lib::ProjFiles::Data)?;
    let current_hash = hash_file(&current_db_file)?;
    if backups.iter().any(|b| b.hash == current_hash) {
        ui::fmt_print(
            "Backup of current blackout already exists",
            ui::ContentType::Error,
            conf,
        );
        return Ok(());
    }
    fs::copy(
        current_db_file,
        lib::get_project_file(lib::ProjFiles::BackupNew)?,
    )?;
    ui::fmt_print("Backup created", ui::ContentType::Success, conf);
    Ok(())
}

pub fn get_backups() -> Result<Vec<Backup>> {
    let mut backups: Vec<Backup> = vec![];
    let files = fs::read_dir(lib::get_project_file(lib::ProjFiles::BackupDir)?)?;
    for f in files {
        let file: fs::DirEntry = f?;
        if file.file_type()?.is_dir() {
            continue;
        }
        let file_path = match file.path().to_str() {
            Some(s) => s.to_owned(),
            None => bail!("Error getting backup file path"),
        };
        if !file_path.contains(".backup.db") {
            continue;
        }
        let hash = hash_file(&file_path)?;
        let timestamp: i64 = file_path
            .split('/')
            .last()
            .unwrap()
            .split('.')
            .next()
            .unwrap()
            .parse()?;
        backups.push(Backup {
            timestamp,
            file_path,
            hash,
        });
    }
    Ok(backups)
}

fn hash_file(file: &str) -> Result<String> {
    ensure!(Path::new(file).exists(), "File {file} not found");
    let mut content: Vec<u8> = vec![];
    let mut f = fs::File::open(file)?;
    f.read_to_end(&mut content)?;
    Ok(hex::encode(md5::compute(content).0))
}
