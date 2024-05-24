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

use std::fs::{create_dir_all, DirEntry, File};
use std::io::{Read, Write};
use std::path::Path;
use std::{env, fs};

use anyhow::{anyhow, bail, ensure, Result};
use chrono::{DateTime, Local};
use colored::Colorize;
use dialoguer::Select;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};
use directories::ProjectDirs;
use serde_derive::{Deserialize, Serialize};
use toml::to_string;
use which::which;

struct Project<T: AsRef<str>> {
    qualifier: T,
    org: T,
    app: T,
}

#[derive(Serialize, Deserialize)]
pub struct BlackoutConfig {
    pub color: bool,
    pub editor: String,
    pub banner: bool,
    pub auto_copy: bool,
    pub icons: bool,
    pub autobackup: bool,
}

#[derive(Clone)]
pub struct Backup {
    pub timestamp: i64,
    pub file_path: String,
    pub hash: String,
}

pub enum ProjFiles {
    BackupDir,
    BackupNew,
    Conf,
    Data,
    WordList,
}

pub enum ContentType {
    Body,
    NoteHeader,
    Error,
    Info,
    Password,
    Success,
    TotpHeader,
    Warn,
}

const PROJECT: Project<&'static str> = Project {
    qualifier: "io",
    org: "ash",
    app: "blackout",
};

const BACKUP_DIR: &str = "backups";
const CONF_FILE: &str = "config.toml";
const DATA_FILE: &str = "blackout.db";
const WL_FILE: &str = "wordlist.txt";

pub fn get_selection_from_user(
    prompt: &str,
    report: bool,
    items: &[String],
    color: bool,
) -> Result<usize> {
    let idx = match color {
        true => Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .report(report)
            .items(items)
            .interact()?,
        false => Select::new()
            .with_prompt(prompt)
            .report(report)
            .items(items)
            .interact()?,
    };
    Ok(idx)
}

pub fn restore_backup(conf: &BlackoutConfig) -> Result<()> {
    let current_db_file = get_project_file(ProjFiles::Data)?;
    let current_hash = hash_file(&current_db_file)?;
    let backups: Vec<Backup> = get_backups()?
        .into_iter()
        .filter(|b| b.hash != current_hash)
        .collect();
    if backups.is_empty() {
        fmt_print(
            "No backups avaiable or current blackout matches the only available backup",
            ContentType::Error,
            conf,
        );
        return Ok(());
    }
    let mut backup_strs: Vec<String> = backups
        .iter()
        .map(|b| format!("{} -> {}", get_time_from_ts(b.timestamp).unwrap(), b.hash))
        .collect();
    backup_strs.push("Cancel".to_string());
    let backup_idx =
        get_selection_from_user("Select backup to restore", true, &backup_strs, conf.color)?;
    if backup_idx == backups.len() {
        return Ok(());
    }
    let backup = backups[backup_idx].clone();
    let backups = get_backups()?;
    if !backups.iter().any(|b| b.hash == current_hash)
        && confirm_with_user("Create backup of current blackout", true, conf.color)?
    {
        create_backup(conf)?;
    }
    fs::remove_file(&current_db_file)?;
    fs::copy(backup.file_path, current_db_file)?;
    fmt_print("Backup restored", ContentType::Success, conf);
    Ok(())
}

pub fn create_backup(conf: &BlackoutConfig) -> Result<()> {
    let backups = get_backups()?;
    let current_db_file = get_project_file(ProjFiles::Data)?;
    let current_hash = hash_file(&current_db_file)?;
    if backups.iter().any(|b| b.hash == current_hash) {
        fmt_print(
            "Backup of current blackout already exists",
            ContentType::Error,
            conf,
        );
        return Ok(());
    }
    fs::copy(current_db_file, get_project_file(ProjFiles::BackupNew)?)?;
    fmt_print("Backup created", ContentType::Success, conf);
    Ok(())
}

pub fn hash_file(file: &str) -> Result<String> {
    ensure!(Path::new(file).exists(), "File {file} not found");
    let mut content: Vec<u8> = vec![];
    let mut f = File::open(file)?;
    f.read_to_end(&mut content)?;
    Ok(hex::encode(md5::compute(content).0))
}

pub fn get_backups() -> Result<Vec<Backup>> {
    let mut backups: Vec<Backup> = vec![];
    let files = fs::read_dir(get_project_file(ProjFiles::BackupDir)?)?;
    for f in files {
        let file: DirEntry = f?;
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

pub fn fmt_print(s: &str, content_type: ContentType, conf: &BlackoutConfig) {
    if conf.color {
        match content_type {
            ContentType::Body => println!("{}", s.bold()),
            ContentType::NoteHeader => {
                println!(
                    "{}",
                    stretch_string(" ".to_string(), None).magenta().underline()
                );
                if conf.icons {
                    let new_s = format!("{}  {}", "󱞂", s);
                    println!(
                        "{}",
                        stretch_string(new_s.to_string(), Some(3))
                            .magenta()
                            .bold()
                            .underline()
                    );
                } else {
                    println!(
                        "{}",
                        stretch_string(s.to_string(), None)
                            .magenta()
                            .bold()
                            .underline()
                    );
                }
            }
            ContentType::Error => {
                if conf.icons {
                    eprintln!("{}  {}", "".red(), s.red().bold());
                } else {
                    eprintln!("{}", s.red().bold());
                }
            }
            ContentType::Info => {
                if conf.icons {
                    println!("{}  {}", "".blue(), s.blue().bold())
                } else {
                    println!("{}", s.blue().bold())
                }
            }
            ContentType::Password => {
                if conf.icons {
                    println!("\n{}  {}\n", "".cyan(), s.cyan().bold())
                } else {
                    println!("\n{}\n", s.cyan().bold())
                }
            }
            ContentType::Success => {
                if conf.icons {
                    println!("{}  {}", "".green(), s.green().bold())
                } else {
                    println!("{}", s.green().bold())
                }
            }
            ContentType::TotpHeader => {
                println!(
                    "{}",
                    stretch_string(" ".to_string(), None).cyan().underline()
                );
                if conf.icons {
                    let new_s = format!("{}  {}", "󰯄", s);
                    println!(
                        "{}",
                        stretch_string(new_s.to_string(), Some(3))
                            .cyan()
                            .bold()
                            .underline()
                    );
                } else {
                    println!(
                        "{}",
                        stretch_string(s.to_string(), None)
                            .cyan()
                            .bold()
                            .underline()
                    );
                }
            }
            ContentType::Warn => {
                if conf.icons {
                    println!("{}  {}", "".yellow(), s.yellow().italic())
                } else {
                    println!("{}", s.yellow().italic())
                }
            }
        }
    } else {
        match content_type {
            ContentType::NoteHeader | ContentType::TotpHeader => {
                println!("{}", stretch_string(" ".to_string(), None).underline());
                println!("{}", stretch_string(s.to_string(), None).underline());
            }
            ContentType::Error => eprintln!("{}", s),
            ContentType::Password => println!("\n{}\n", s),
            _ => println!("{}", s),
        }
    }
}

pub fn get_project_file(file: ProjFiles) -> Result<String> {
    if let Some(proj) = ProjectDirs::from(PROJECT.qualifier, PROJECT.org, PROJECT.app) {
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

pub fn setup_file_struct() -> Result<()> {
    if let Some(proj) = ProjectDirs::from(PROJECT.qualifier, PROJECT.org, PROJECT.app) {
        if !proj.config_dir().exists() {
            create_dir_all(proj.config_dir())?;
        }
        if !proj.data_dir().exists() {
            create_dir_all(proj.data_dir())?;
            create_dir_all(format!(
                "{}/{}",
                proj.data_dir().to_str().unwrap(),
                BACKUP_DIR
            ))?;
        }
        let conf_file = format!("{}/{}", proj.config_dir().to_str().unwrap(), CONF_FILE);
        let wl_file = format!("{}/{}", proj.config_dir().to_str().unwrap(), WL_FILE);
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
            write_init_config()?;
        }
        return Ok(());
    }
    Err(anyhow!("Could not create project directories"))
}

pub fn get_config() -> Result<BlackoutConfig> {
    let toml_string = read_file(&get_project_file(ProjFiles::Conf)?)?;
    let conf: BlackoutConfig = toml::from_str(&toml_string)?;
    Ok(conf)
}

pub fn write_init_config() -> Result<()> {
    let color = confirm_with_user("Enable color", true, false)?;
    let default_editor = match env::consts::OS {
        "windows" => "notepad".to_string(),
        "macos" => "nano".to_string(),
        _ => "vi".to_string(),
    };
    let editor: String = match color {
        true => Input::with_theme(&ColorfulTheme::default())
            .with_prompt("What editor would you like to use?")
            .default(default_editor)
            .validate_with(|input: &String| -> Result<(), &str> {
                match which(input) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Program not found"),
                }
            })
            .interact_text()?,
        false => Input::new()
            .with_prompt("What editor would you like to use?")
            .default(default_editor)
            .validate_with(|input: &String| -> Result<(), &str> {
                match which(input) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Program not found"),
                }
            })
            .interact_text()?,
    };
    let auto_copy = confirm_with_user(
        "Enable auto copy of generated passwords/passphrases to clipboard",
        false,
        color,
    )?;
    let banner = confirm_with_user("Enable banner on interactive startup", true, color)?;
    let icons = confirm_with_user(
        "Enable icons (requires nerd fonts to be installed, is ignored if color is false)",
        true,
        color,
    )?;
    let autobackup = confirm_with_user(
        "Autobackup blackout data when entries are added or change",
        false,
        color,
    )?;
    let mut file = File::create(get_project_file(ProjFiles::Conf)?)?;
    let conf = BlackoutConfig {
        color,
        editor,
        banner,
        auto_copy,
        icons,
        autobackup,
    };
    file.write_all(to_string(&conf)?.as_bytes())?;
    fmt_print(
        "NOTE: Params can be changed in config file.",
        ContentType::Info,
        &conf,
    );
    Ok(())
}

pub fn get_timestamp() -> i64 {
    Local::now().timestamp()
}

pub fn get_time_from_ts(ts: i64) -> Result<String> {
    let dt: DateTime<Local> = match DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.with_timezone(&Local),
        None => bail!("Invalid Timestamp"),
    };
    Ok(dt.format("%Y-%m-%d %H%M").to_string())
}

pub fn read_file(path: &str) -> Result<String> {
    let mut s = String::new();
    let mut f = File::open(path)?;
    f.read_to_string(&mut s)?;
    Ok(s)
}

pub fn confirm_with_user(prompt: &str, default: bool, color: bool) -> Result<bool> {
    let ans = match color {
        true => Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(default)
            .show_default(true)
            .wait_for_newline(true)
            .interact()?,
        false => Confirm::new()
            .with_prompt(prompt)
            .default(default)
            .show_default(true)
            .wait_for_newline(true)
            .interact()?,
    };
    Ok(ans)
}

fn stretch_string(mut s: String, add: Option<u8>) -> String {
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
