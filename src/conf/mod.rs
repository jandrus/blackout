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
use std::io::Write;

use anyhow::Result;
use serde_derive::{Deserialize, Serialize};
use toml::to_string;

use crate::ui;

#[derive(Serialize, Deserialize)]
pub struct BlackoutConfig {
    pub color: bool,
    pub editor: String,
    pub banner: bool,
    pub auto_copy: bool,
    pub icons: bool,
    pub autobackup: bool,
}

pub fn get_config() -> Result<BlackoutConfig> {
    let toml_string = lib::read_file(&lib::get_project_file(lib::ProjFiles::Conf)?)?;
    let conf: BlackoutConfig = toml::from_str(&toml_string)?;
    Ok(conf)
}

pub fn write_init_config() -> Result<()> {
    let color = ui::confirm_with_user("Enable color", true, false)?;
    let editor = ui::get_user_editor(color)?;
    let auto_copy = ui::confirm_with_user(
        "Enable auto copy of generated passwords/passphrases to clipboard",
        false,
        color,
    )?;
    let banner = ui::confirm_with_user("Enable banner on interactive startup", true, color)?;
    let icons = ui::confirm_with_user(
        "Enable icons (requires nerd fonts to be installed, is ignored if color is false)",
        true,
        color,
    )?;
    let autobackup = ui::confirm_with_user(
        "Autobackup blackout data when entries are added or change",
        false,
        color,
    )?;
    let mut file = File::create(lib::get_project_file(lib::ProjFiles::Conf)?)?;
    let conf = BlackoutConfig {
        color,
        editor,
        banner,
        auto_copy,
        icons,
        autobackup,
    };
    file.write_all(to_string(&conf)?.as_bytes())?;
    ui::fmt_print(
        "NOTE: Params can be changed in config file.",
        ui::ContentType::Info,
        &conf,
    );
    Ok(())
}
