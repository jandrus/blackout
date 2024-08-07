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

use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{anyhow, Result};

use crate::{conf, db, ui};

pub fn initialized() -> bool {
    Path::new(&lib::get_project_file(lib::ProjFiles::Data).unwrap_or("DNE".to_string())).exists()
}

pub fn initialize_db(conf: &conf::BlackoutConfig) -> Result<()> {
    ui::fmt_print(
        "No entries detected: initiating blackout setup",
        ui::ContentType::Warn,
        conf,
    );
    let pass = ui::get_user_password("Enter initial blackout password", conf.color, true)?;
    db::init(&pass)?;
    ui::fmt_print("Password accepted", ui::ContentType::Success, conf);
    Ok(())
}

pub fn setup_file_struct() -> Result<()> {
    if let Some(proj) = lib::get_project() {
        if !proj.config_dir().exists() {
            create_dir_all(proj.config_dir())?;
        }
        if !proj.data_dir().exists() {
            create_dir_all(proj.data_dir())?;
            create_dir_all(format!(
                "{}/{}",
                proj.data_dir().to_str().unwrap(),
                lib::BACKUP_DIR
            ))?;
        }
        let conf_file = format!("{}/{}", proj.config_dir().to_str().unwrap(), lib::CONF_FILE);
        let wl_file = format!("{}/{}", proj.config_dir().to_str().unwrap(), lib::WL_FILE);
        if !Path::new(&wl_file).exists() {
            println!("Wordlist not detected: downloading");
            let mut resp = reqwest::blocking::get(
                "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
            )?;
            let mut body = String::new();
            resp.read_to_string(&mut body).unwrap();
            let mut wl_file = File::create(wl_file)?;
            write!(wl_file, "{}", body).unwrap();
        }
        if !Path::new(&conf_file).exists() {
            println!("Configuration not detected: initiating config setup");
            conf::write_init_config()?;
        }
        return Ok(());
    }
    Err(anyhow!("Could not create project directories"))
}
