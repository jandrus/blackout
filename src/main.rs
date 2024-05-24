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
use std::{fs, process};
use std::{path::Path, usize};

use anyhow::{anyhow, bail, Result};
use chrono::Local;
use clap::{Arg, ArgMatches, Command};
use clipboard::{ClipboardContext, ClipboardProvider};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Editor, Input, MultiSelect, Password};
use secstr::{SecStr, SecVec};
use serde_derive::{Deserialize, Serialize};
use serde_json::json;

mod db;
mod sec;

#[derive(Clone, PartialEq)]
enum Action {
    Add,
    ChangePass,
    CreateBackup,
    Delete,
    Edit,
    Exit,
    Export,
    Fetch,
    Generate,
    ListLabels,
    RestoreBackup,
}

#[derive(Clone, PartialEq)]
enum SubAction {
    Both,
    Note,
    Totp,
    Password,
    Passphrase,
}

impl Action {
    fn get_str(&self, sub_action: Option<SubAction>) -> &str {
        match self {
            Action::Add => match sub_action {
                Some(SubAction::Note) => "Add note",
                Some(SubAction::Totp) => "Add totp",
                _ => "Add note or totp url",
            },
            Action::ChangePass => "Change master password",
            Action::CreateBackup => "Create backup",
            Action::Delete => match sub_action {
                Some(SubAction::Note) => "Delete note",
                Some(SubAction::Totp) => "Delete totp",
                _ => "Delete note or totp url",
            },
            Action::Edit => match sub_action {
                Some(SubAction::Note) => "Edit note",
                Some(SubAction::Totp) => "Edit totp",
                _ => "Edit note or totp url",
            },
            Action::Exit => "Exit",
            Action::Export => match sub_action {
                Some(SubAction::Both) => "Export both",
                Some(SubAction::Note) => "Export notes",
                Some(SubAction::Totp) => "Export totp urls",
                _ => "Export",
            },
            Action::Fetch => match sub_action {
                Some(SubAction::Note) => "Fetch note",
                Some(SubAction::Totp) => "Fetch totp",
                _ => "Fetch note or totp code",
            },
            Action::Generate => match sub_action {
                Some(SubAction::Password) => "Generate password",
                Some(SubAction::Passphrase) => "Generate passphrase",
                _ => "Generate password or passphrase",
            },
            Action::ListLabels => match sub_action {
                Some(SubAction::Both) => "List both",
                Some(SubAction::Note) => "List note labels",
                Some(SubAction::Totp) => "List totp labels",
                _ => "List note or totp labels",
            },
            Action::RestoreBackup => "Restore backup",
        }
    }
}

const BANNER: &str = "
__________.__                 __                 __
\\______   \\  | _____    ____ |  | ______  __ ___/  |_
 |    |  _/  | \\__  \\ _/ ___\\|  |/ /  _ \\|  |  \\   __|
 |    |   \\  |__/ __ \\|  \\___|    <  <_> )  |  /|  |
 |______  /____(____  /\\___  >__|_ \\____/|____/ |__|
        \\/          \\/     \\/     \\/
";
const AVAIL_ACTIONS: &[Action] = &[
    Action::Fetch,
    Action::Add,
    Action::Edit,
    Action::Generate,
    Action::ListLabels,
    Action::Delete,
    Action::ChangePass,
    Action::CreateBackup,
    Action::RestoreBackup,
    Action::Export,
    Action::Exit,
];
const MIN_PASS_SIZE: usize = 10;

fn main() {
    // Setup file structure
    if let Err(e) = lib::setup_file_struct() {
        eprintln!("Error setting up file structure: {}", e);
        process::exit(1);
    }
    // Get conf from file
    let conf = match lib::get_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error getting configuration: {}", e);
            process::exit(1);
        }
    };
    // MATCHES
    let matches = get_matches();
    // Matches -> backup
    if matches.get_flag("backup") {
        if let Err(e) = lib::create_backup(&conf) {
            kill(&format!("Error creating backup: {}", e), &conf);
        }
        process::exit(0);
    }
    match matches.subcommand() {
        // Matches -> generate
        Some(("generate", gen_matches)) => match gen_matches.subcommand() {
            // Matches -> generate -> pass
            Some(("pass", gen_pass_matches)) => {
                if gen_pass_matches.get_flag("interactive") {
                    if let Err(e) = generate_password_interactive(&conf) {
                        kill(&format!("Error generating password: {}", e), &conf);
                    }
                    process::exit(0);
                }
                let selections: Vec<sec::PasswordOptions> = vec![
                    sec::PasswordOptions::AlphaLower,
                    sec::PasswordOptions::AlphaUpper,
                    sec::PasswordOptions::Nums,
                    sec::PasswordOptions::Symbols,
                ];
                let len: u8 = match gen_pass_matches.contains_id("length") {
                    true => gen_pass_matches
                        .get_one::<String>("length")
                        .unwrap()
                        .to_string()
                        .parse::<u8>()
                        .unwrap_or(15),
                    false => 15,
                };
                let generated_pass = sec::gen_pass(len, selections);
                let msg = format!("Generated password: {}", generated_pass);
                lib::fmt_print(&msg, lib::ContentType::Password, &conf);
                if conf.auto_copy {
                    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                    ctx.set_contents(generated_pass).unwrap();
                    lib::fmt_print(
                        "Password copied to clipboard",
                        lib::ContentType::Warn,
                        &conf,
                    );
                }
                process::exit(0);
            }
            // Matches -> generate -> phrase
            Some(("phrase", gen_phrase_matches)) => {
                let len: u8 = match gen_phrase_matches.contains_id("words") {
                    true => gen_phrase_matches
                        .get_one::<String>("words")
                        .unwrap()
                        .to_string()
                        .parse::<u8>()
                        .unwrap_or(5),
                    false => 5,
                };
                match sec::gen_passphrase(len) {
                    Ok(phrase) => {
                        let msg = format!("Generated passphrase: {}", phrase);
                        lib::fmt_print(&msg, lib::ContentType::Password, &conf);
                        if conf.auto_copy {
                            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                            ctx.set_contents(phrase).unwrap();
                            lib::fmt_print(
                                "Passphrase copied to clipboard",
                                lib::ContentType::Warn,
                                &conf,
                            );
                        }
                    }
                    Err(e) => {
                        kill(&format!("Failed generate passphrase: {}", e), &conf);
                    }
                }
                process::exit(0);
            }
            _ => unreachable!(),
        },
        // Matches -> fetch
        Some(("fetch", fetch_matches)) => {
            let pass =
                match Path::new(&lib::get_project_file(lib::ProjFiles::Data).unwrap()).exists() {
                    true => get_user_password("Unlock blackout", conf.color, false).unwrap(),
                    false => {
                        kill("Blackout has not been initiated (no entries exist)", &conf);
                    }
                };
            match fetch_matches.subcommand() {
                Some(("note", fetch_note_matches)) => {
                    if db::is_empty(&pass, &db::EntryType::Note).unwrap() {
                        kill("No notes found", &conf);
                    }
                    let entry = match fetch_note_matches.contains_id("label") {
                        true => {
                            let label = fetch_note_matches
                                .get_one::<String>("label")
                                .unwrap()
                                .to_string();
                            match db::get_entry(&pass, label, &db::EntryType::Note) {
                                Ok(ent) => ent,
                                Err(e) => {
                                    kill(&format!("Failed to get note: {}", e), &conf);
                                }
                            }
                        }
                        false => match select_entry(&pass, conf.color, db::EntryType::Note) {
                            Ok(ent) => ent,
                            Err(e) => {
                                kill(&format!("Error getting entry from user: {}", e), &conf);
                            }
                        },
                    };
                    if let Err(e) = display_entry(entry, None, &conf) {
                        kill(&format!("Error displaying note: {}", e), &conf);
                    }
                    process::exit(0);
                }
                Some(("totp", fetch_totp_matches)) => {
                    if db::is_empty(&pass, &db::EntryType::Totp).unwrap() {
                        kill("No totp codes found", &conf);
                    }
                    let entry = match fetch_totp_matches.contains_id("label") {
                        true => {
                            let label = fetch_totp_matches
                                .get_one::<String>("label")
                                .unwrap()
                                .to_string();
                            match db::get_entry(&pass, label, &db::EntryType::Totp) {
                                Ok(ent) => ent,
                                Err(e) => {
                                    kill(&format!("Failed to get totp code: {}", e), &conf);
                                }
                            }
                        }
                        false => match select_entry(&pass, conf.color, db::EntryType::Totp) {
                            Ok(ent) => ent,
                            Err(e) => {
                                kill(&format!("Error getting entry from user: {}", e), &conf);
                            }
                        },
                    };
                    let otp_code = match sec::totp_code(&entry.content) {
                        Ok(s) => s,
                        Err(e) => {
                            kill(&format!("Error processing totp: {}", e), &conf);
                        }
                    };
                    if let Err(e) = display_entry(entry, Some(&otp_code), &conf) {
                        kill(&format!("Error displaying entry: {}", e), &conf);
                    }
                    process::exit(0);
                }
                _ => unreachable!(),
            }
        }
        // Matches -> export
        Some(("export", export_matches)) => {
            let mut format = 2;
            if export_matches.get_flag("json") {
                format = 0;
            } else if export_matches.get_flag("toml") {
                format = 1;
            }
            if format == 2 {
                if let Err(e) = fs::copy(
                    lib::get_project_file(lib::ProjFiles::Data).unwrap(),
                    "blackout.db",
                ) {
                    kill(&format!("Error exporting database: {}", e), &conf)
                }
                process::exit(0);
            }
            let pass =
                match Path::new(&lib::get_project_file(lib::ProjFiles::Data).unwrap()).exists() {
                    true => get_user_password("Unlock blackout", conf.color, false).unwrap(),
                    false => {
                        kill("Blackout has not been initiated (no entries exist)", &conf);
                    }
                };
            lib::fmt_print(
                "WARNING: this will output all of your data in CLEAR TEXT",
                lib::ContentType::Warn,
                &conf,
            );
            if lib::confirm_with_user("Are you sure", false, conf.color).unwrap() {
                let sub_action = get_subaction(&pass, Action::Export, conf.color).unwrap();
                if let Err(e) = export(&pass, sub_action, format == 0) {
                    kill(&format!("Error exporting notes: {}", e), &conf);
                }
            }
            process::exit(0);
        }
        // Matches -> list
        Some(("list", list_matches)) => {
            let pass =
                match Path::new(&lib::get_project_file(lib::ProjFiles::Data).unwrap()).exists() {
                    true => get_user_password("Unlock blackout", conf.color, false).unwrap(),
                    false => {
                        kill("Blackout has not been initiated (no entries exist)", &conf);
                    }
                };
            match list_matches.subcommand() {
                Some(("note", _)) | Some(("notes", _)) => {
                    if db::is_empty(&pass, &db::EntryType::Note).unwrap() {
                        kill("No notes found", &conf);
                    }
                    if let Err(e) = list_labels(&pass, db::EntryType::Note, &conf) {
                        kill(&format!("Error listing entries: {}", e), &conf);
                    }
                    process::exit(0);
                }
                Some(("totp", _)) => {
                    if db::is_empty(&pass, &db::EntryType::Totp).unwrap() {
                        kill("No totp codes found", &conf);
                    }
                    if let Err(e) = list_labels(&pass, db::EntryType::Totp, &conf) {
                        kill(&format!("Error listing entries: {}", e), &conf);
                    }
                    process::exit(0);
                }
                _ => {
                    if !db::is_empty(&pass, &db::EntryType::Note).unwrap() {
                        if let Err(e) = list_labels(&pass, db::EntryType::Note, &conf) {
                            kill(&format!("Error listing entries: {}", e), &conf);
                        }
                    }
                    if !db::is_empty(&pass, &db::EntryType::Totp).unwrap() {
                        if let Err(e) = list_labels(&pass, db::EntryType::Totp, &conf) {
                            kill(&format!("Error listing entries: {}", e), &conf);
                        }
                    }
                    process::exit(0);
                }
            }
        }
        // Matches -> add
        Some(("add", add_matches)) => {
            let pass =
                match Path::new(&lib::get_project_file(lib::ProjFiles::Data).unwrap()).exists() {
                    true => get_user_password("Unlock blackout", conf.color, false).unwrap(),
                    false => {
                        kill("Blackout has not been initiated (no entries exist)", &conf);
                    }
                };
            let sub_action = match add_matches.subcommand() {
                Some(("note", _)) => SubAction::Note,
                Some(("totp", _)) => SubAction::Totp,
                _ => get_subaction(&pass, Action::Add, conf.color).unwrap(),
            };
            match sub_action {
                SubAction::Note => {
                    let entry = match get_user_entry(&pass, &conf, db::EntryType::Note) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Failed to get entry from user: {}", e), &conf);
                        }
                    };
                    match db::add_entry(&pass, entry) {
                        Ok(_) => {
                            lib::fmt_print("Entry added", lib::ContentType::Success, &conf);
                        }
                        Err(e) => {
                            kill(&format!("Failed to add entry: {}", e), &conf);
                        }
                    }
                }
                SubAction::Totp => {
                    let entry = match get_user_entry(&pass, &conf, db::EntryType::Totp) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Failed to get entry from user: {}", e), &conf);
                        }
                    };
                    match db::add_entry(&pass, entry) {
                        Ok(_) => {
                            lib::fmt_print("Entry added", lib::ContentType::Success, &conf);
                        }
                        Err(e) => {
                            kill(&format!("Failed to add entry: {}", e), &conf);
                        }
                    }
                }
                _ => unreachable!("Invalid subaction for ADD"),
            }
            if conf.autobackup {
                if let Err(e) = lib::create_backup(&conf) {
                    kill(&format!("Error creating backup: {}", e), &conf);
                }
            }
            process::exit(0);
        }
        _ => (),
    }
    // Print banner
    if conf.banner {
        if conf.color {
            println!("{}", Local::now().to_rfc2822().red());
            println!("{}", BANNER.red());
        } else {
            println!("{}", Local::now().to_rfc2822());
            println!("{}", BANNER);
        }
    }
    let mut has_edited = false;
    // Get password
    let password: SecVec<u8> =
        match Path::new(&lib::get_project_file(lib::ProjFiles::Data).unwrap()).exists() {
            true => {
                // Get password for existing DB
                get_user_password("Unlock blackout", conf.color, false).unwrap()
            }
            false => {
                // Setup DB (encrypted) if not exists
                lib::fmt_print(
                    "No entries detected: initiating blackout setup",
                    lib::ContentType::Warn,
                    &conf,
                );
                let pass =
                    get_user_password("Enter initial blackout password", conf.color, true).unwrap();
                if let Err(e) = db::init(&pass) {
                    kill(&format!("Error setting up database: {}", e), &conf);
                }
                lib::fmt_print("Password accepted", lib::ContentType::Success, &conf);
                pass
            }
        };
    loop {
        match get_action(&password, conf.color).unwrap() {
            // ADD Note or Totp
            Action::Add => match get_subaction(&password, Action::Add, conf.color).unwrap() {
                SubAction::Note => {
                    let entry = match get_user_entry(&password, &conf, db::EntryType::Note) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Failed to get entry from user: {}", e), &conf);
                        }
                    };
                    match db::add_entry(&password, entry) {
                        Ok(_) => {
                            lib::fmt_print("Entry added", lib::ContentType::Success, &conf);
                        }
                        Err(e) => {
                            kill(&format!("Failed to add entry: {}", e), &conf);
                        }
                    }
                    has_edited = true;
                }
                SubAction::Totp => {
                    let entry = match get_user_entry(&password, &conf, db::EntryType::Totp) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Failed to get entry from user: {}", e), &conf);
                        }
                    };
                    match db::add_entry(&password, entry) {
                        Ok(_) => {
                            lib::fmt_print("Entry added", lib::ContentType::Success, &conf);
                        }
                        Err(e) => {
                            kill(&format!("Failed to add entry: {}", e), &conf);
                        }
                    }
                    has_edited = true;
                }
                _ => unreachable!("Invalid subaction for ADD"),
            },
            // CHANGE Master Password
            Action::ChangePass => {
                lib::fmt_print(
                    "WARNING: Changing blackout password. This action is irreversible.",
                    lib::ContentType::Warn,
                    &conf,
                );
                let current_pass =
                    get_user_password("Enter current password", conf.color, false).unwrap();
                let new_pass = get_user_password("Enter NEW password", conf.color, true).unwrap();
                match db::rekey(&current_pass, &new_pass) {
                    Ok(_) => lib::fmt_print(
                        "Password updated successfully",
                        lib::ContentType::Success,
                        &conf,
                    ),
                    Err(e) => {
                        kill(&format!("Error updating password: {}", e), &conf);
                    }
                }
                process::exit(0);
            }
            // CREATE Backup
            Action::CreateBackup => {
                if let Err(e) = lib::create_backup(&conf) {
                    kill(&format!("Error creating backup: {}", e), &conf);
                }
            }
            // DELETE Note or Totp
            Action::Delete => match get_subaction(&password, Action::Delete, conf.color).unwrap() {
                SubAction::Note => {
                    let entry = match select_entry(&password, conf.color, db::EntryType::Note) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Error getting entry from user: {}", e), &conf);
                        }
                    };
                    lib::fmt_print(
                        "WARNING ACTION IS IRREVERSIBLE (backup is recommended)",
                        lib::ContentType::Warn,
                        &conf,
                    );
                    let msg = format!("Are you sure you want to delete the note {}", entry.label);
                    let confirm = lib::confirm_with_user(&msg, false, conf.color).unwrap();
                    if confirm {
                        match db::delte_entry(&password, &entry) {
                            Ok(_) => {
                                let msg = format!("DELETED {}", &entry.label);
                                lib::fmt_print(&msg, lib::ContentType::Warn, &conf);
                            }
                            Err(e) => {
                                kill(&format!("Error deleting note: {}", e), &conf);
                            }
                        }
                    }
                    has_edited = true;
                }
                SubAction::Totp => {
                    let entry = match select_entry(&password, conf.color, db::EntryType::Totp) {
                        Ok(t) => t,
                        Err(e) => {
                            kill(&format!("Error getting entry from user: {}", e), &conf);
                        }
                    };
                    lib::fmt_print(
                        "WARNING ACTION IS IRREVERSIBLE (backup is recommended)",
                        lib::ContentType::Warn,
                        &conf,
                    );
                    let msg = format!(
                        "Are you sure you want to delete the totp code {}",
                        &entry.label
                    );
                    let confirm = lib::confirm_with_user(&msg, false, conf.color).unwrap();
                    if confirm {
                        match db::delte_entry(&password, &entry) {
                            Ok(_) => {
                                let msg = format!("DELETED {}", &entry.label);
                                lib::fmt_print(&msg, lib::ContentType::Warn, &conf);
                            }
                            Err(e) => {
                                kill(&format!("Error deleting totp: {}", e), &conf);
                            }
                        }
                    }
                    has_edited = true;
                }
                _ => unreachable!("Invalid subaction for ADD"),
            },
            // EDIT Note or Totp
            Action::Edit => match get_subaction(&password, Action::Edit, conf.color).unwrap() {
                SubAction::Note => {
                    let mut entry = match select_entry(&password, conf.color, db::EntryType::Note) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Error getting entry from user: {}", e), &conf);
                        }
                    };
                    if let Some(content) = Editor::new()
                        .executable(&conf.editor)
                        .require_save(true)
                        .edit(&entry.content)
                        .unwrap()
                    {
                        entry.content = content;
                    }
                    match db::update_entry(&password, entry) {
                        Ok(_) => lib::fmt_print("Update saved", lib::ContentType::Success, &conf),
                        Err(e) => {
                            kill(&format!("Error updating entry: {}", e), &conf);
                        }
                    }
                    has_edited = true;
                }
                SubAction::Totp => {
                    let mut entry = match select_entry(&password, conf.color, db::EntryType::Totp) {
                        Ok(t) => t,
                        Err(e) => {
                            kill(&format!("Error getting entry from user: {}", e), &conf);
                        }
                    };
                    let content = match conf.color {
                        true => Password::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter totp URL")
                            .validate_with(|input: &String| -> Result<(), String> {
                                sec::validate_totp(input)
                            })
                            .interact()
                            .unwrap(),
                        false => Password::new()
                            .with_prompt("Enter totp URL")
                            .validate_with(|input: &String| -> Result<(), String> {
                                sec::validate_totp(input)
                            })
                            .interact()
                            .unwrap(),
                    };
                    entry.content = content;
                    match db::update_entry(&password, entry) {
                        Ok(_) => lib::fmt_print("Update saved", lib::ContentType::Success, &conf),
                        Err(e) => {
                            kill(&format!("Error updating entry: {}", e), &conf);
                        }
                    }
                    has_edited = true;
                }
                _ => unreachable!("Invalid subaction for ADD"),
            },
            // EXIT
            Action::Exit => {
                break;
            }
            // EXPORT Notes or totp urls
            Action::Export => {
                let selection = lib::get_selection_from_user(
                    "file type output",
                    true,
                    &[
                        "json".to_owned(),
                        "toml".to_owned(),
                        "database (data remains encrypted). Use this to migrate to new machine."
                            .to_owned(),
                    ],
                    conf.color,
                )
                .unwrap();
                if selection == 2 {
                    if let Err(e) = fs::copy(
                        lib::get_project_file(lib::ProjFiles::Data).unwrap(),
                        "blackout.db",
                    ) {
                        kill(&format!("Error exporting database: {}", e), &conf)
                    }
                    continue;
                }
                lib::fmt_print(
                    "WARNING: this will output all of your data in CLEAR TEXT",
                    lib::ContentType::Warn,
                    &conf,
                );
                if lib::confirm_with_user("Are you sure", false, conf.color).unwrap() {
                    let sub_action = get_subaction(&password, Action::Export, conf.color).unwrap();
                    if let Err(e) = export(&password, sub_action, selection == 0) {
                        kill(&format!("Error exporting notes: {}", e), &conf);
                    }
                }
            }
            // GENERATE Password or Passphrase
            Action::Generate => match get_subaction(&password, Action::Generate, conf.color)
                .unwrap()
            {
                SubAction::Password => {
                    if let Err(e) = generate_password_interactive(&conf) {
                        kill(&format!("Error generating password: {}", e), &conf);
                    }
                }
                SubAction::Passphrase => {
                    let passphrase_len =
                        get_len_from_user("Number of words", "5", conf.color).unwrap();
                    match sec::gen_passphrase(passphrase_len) {
                        Ok(phrase) => {
                            let msg = format!("Generated passphrase: {}", phrase);
                            lib::fmt_print(&msg, lib::ContentType::Password, &conf);
                            if conf.auto_copy {
                                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                                ctx.set_contents(phrase).unwrap();
                                lib::fmt_print(
                                    "Passphrase copied to clipboard",
                                    lib::ContentType::Warn,
                                    &conf,
                                );
                            }
                        }
                        Err(e) => {
                            kill(&format!("Failed generate passphrase: {}", e), &conf);
                        }
                    }
                }
                _ => unreachable!("Invalid subaction for GENERATE"),
            },
            // FETCH Note or Totp
            Action::Fetch => match get_subaction(&password, Action::Fetch, conf.color).unwrap() {
                SubAction::Note => {
                    let entry = match select_entry(&password, conf.color, db::EntryType::Note) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Error getting entry from user: {}", e), &conf);
                        }
                    };
                    if let Err(e) = display_entry(entry, None, &conf) {
                        kill(&format!("Error displaying entry: {}", e), &conf);
                    }
                }
                SubAction::Totp => {
                    let entry = match select_entry(&password, conf.color, db::EntryType::Totp) {
                        Ok(ent) => ent,
                        Err(e) => {
                            kill(&format!("Error getting entry from user: {}", e), &conf);
                        }
                    };
                    let otp_code = match sec::totp_code(&entry.content) {
                        Ok(s) => s,
                        Err(e) => {
                            kill(&format!("Error processing totp: {}", e), &conf);
                        }
                    };
                    if let Err(e) = display_entry(entry, Some(&otp_code), &conf) {
                        kill(&format!("Error displaying entry: {}", e), &conf);
                    }
                }
                _ => unreachable!("Invalid subaction for FETCH"),
            },
            // List Labels
            Action::ListLabels => {
                match get_subaction(&password, Action::ListLabels, conf.color).unwrap() {
                    SubAction::Both => {
                        if let Err(e) = list_labels(&password, db::EntryType::Note, &conf) {
                            kill(&format!("Error listing entries: {}", e), &conf);
                        }
                        if let Err(e) = list_labels(&password, db::EntryType::Totp, &conf) {
                            kill(&format!("Error listing entries: {}", e), &conf);
                        }
                    }
                    SubAction::Note => {
                        if let Err(e) = list_labels(&password, db::EntryType::Note, &conf) {
                            kill(&format!("Error listing entries: {}", e), &conf);
                        }
                    }
                    SubAction::Totp => {
                        if let Err(e) = list_labels(&password, db::EntryType::Totp, &conf) {
                            kill(&format!("Error listing entries: {}", e), &conf);
                        }
                    }
                    _ => unreachable!("Invalid subaction for ListLabels"),
                }
            }
            // Restore Backup
            Action::RestoreBackup => match lib::restore_backup(&conf) {
                Ok(_) => (),
                Err(e) => {
                    kill(&format!("Error creating backup: {}", e), &conf);
                }
            },
        }
    }
    if has_edited && conf.autobackup {
        if let Err(e) = lib::create_backup(&conf) {
            kill(&format!("Error creating backup: {}", e), &conf);
        }
    }
    if conf.color {
        println!("{}", "Goodbye".green().bold());
    } else {
        println!("Goodbye");
    }
}

fn get_user_password(prompt: &str, color: bool, new: bool) -> Result<SecVec<u8>> {
    if new {
        let pass = SecStr::from(match color {
            true => Password::with_theme(&ColorfulTheme::default())
                .with_prompt(prompt)
                .with_confirmation("Repeat password", "Error: passwords do not match.")
                .validate_with(|input: &String| -> Result<(), String> {
                    validate_password_len(input)
                })
                .interact()?,
            false => Password::new()
                .with_prompt(prompt)
                .with_confirmation("Repeat password", "Error: passwords do not match.")
                .validate_with(|input: &String| -> Result<(), String> {
                    validate_password_len(input)
                })
                .interact()?,
        });
        return Ok(pass);
    }
    let pass = SecStr::from(match color {
        true => Password::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<(), String> {
                db::validate_password_with_db(input)
            })
            .report(false)
            .interact()?,
        false => Password::new()
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<(), String> {
                db::validate_password_with_db(input)
            })
            .report(false)
            .interact()?,
    });
    Ok(pass)
}

fn get_password_gen_params(color: bool) -> Result<(u8, Vec<sec::PasswordOptions>)> {
    let password_len = get_len_from_user("Password length", "15", color)?;
    let options: Vec<(&str, bool)> = vec![
        ("Include numbers", true),
        ("Include lowercase", true),
        ("Include uppercase", true),
        ("Include symbols \"!#$%&()*+,-./<=>?@[]^_{|}~\"", true),
        ("No similar characters \"i, l, 1, L, o, 0, O\"", false),
    ];
    let selected_options: Vec<sec::PasswordOptions> = match color {
        true => MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Password settings")
            .report(false)
            .items_checked(&options)
            .interact()
            .unwrap()
            .into_iter()
            .map(sec::map_options)
            .collect(),
        false => MultiSelect::new()
            .with_prompt("Password settings")
            .report(false)
            .items_checked(&options)
            .interact()
            .unwrap()
            .into_iter()
            .map(sec::map_options)
            .collect(),
    };
    Ok((password_len, selected_options))
}

fn display_entry(
    entry: db::Entry,
    otp_code: Option<&str>,
    conf: &lib::BlackoutConfig,
) -> Result<()> {
    match entry.entry_type {
        db::EntryType::Note => {
            let header_msg = format!(
                "{} (last updated: {})",
                entry.label,
                lib::get_time_from_ts(entry.timestamp)?
            );
            lib::fmt_print(&header_msg, lib::ContentType::NoteHeader, conf);
            lib::fmt_print(&entry.content, lib::ContentType::Body, conf);
            lib::fmt_print(&entry.label, lib::ContentType::NoteHeader, conf);
        }
        db::EntryType::Totp => {
            let header_msg = format!("TOTP {}", entry.label);
            lib::fmt_print(&header_msg, lib::ContentType::TotpHeader, conf);
            if let Some(code) = otp_code {
                lib::fmt_print(code, lib::ContentType::Body, conf);
            }
            lib::fmt_print(&entry.label, lib::ContentType::TotpHeader, conf);
        }
    }
    println!();
    Ok(())
}

fn list_labels(
    pass: &SecVec<u8>,
    entry_type: db::EntryType,
    conf: &lib::BlackoutConfig,
) -> Result<()> {
    let icon = match entry_type {
        db::EntryType::Note => {
            lib::fmt_print("Available Notes", lib::ContentType::NoteHeader, conf);
            if conf.color {
                println!("{}", "Notes".blue().bold());
            } else {
                println!("Notes");
            }
            match conf.icons {
                true => "󱞂 ",
                false => "",
            }
        }
        db::EntryType::Totp => {
            lib::fmt_print("Available TOTP Codes", lib::ContentType::TotpHeader, conf);
            if conf.color {
                println!("{}", "TOTP".blue().bold());
            } else {
                println!("TOTP");
            }
            match conf.icons {
                true => "󰯄 ",
                false => "",
            }
        }
    };
    let mut catagories = db::get_catagories(pass, &entry_type)?;
    catagories.sort();
    let last_cat = catagories.last().unwrap().clone();
    for catagory in catagories {
        if catagory == last_cat {
            if conf.color {
                println!("└── {}", catagory.blue());
            } else {
                println!("└── {}", catagory);
            }
            let mut labels = db::get_labels(pass, &entry_type, Some(&catagory))?;
            labels.sort();
            let last_label = labels.last().unwrap().clone();
            for label in labels {
                if label == last_label {
                    if conf.color {
                        println!("    └── {}{}", icon.green(), label.green())
                    } else {
                        println!("    └── {}", label)
                    }
                } else if conf.color {
                    println!("    ├── {}{}", icon.green(), label.green())
                } else {
                    println!("    ├── {}", label)
                }
            }
        } else {
            if conf.color {
                println!("├── {}", catagory.blue());
            } else {
                println!("├── {}", catagory);
            }
            let mut labels = db::get_labels(pass, &entry_type, Some(&catagory))?;
            labels.sort();
            let last_label = labels.last().unwrap().clone();
            for label in labels {
                if label == last_label {
                    if conf.color {
                        println!("│   └── {}{}", icon.green(), label.green())
                    } else {
                        println!("│   └── {}", label)
                    }
                } else if conf.color {
                    println!("│   ├── {}{}", icon.green(), label.green())
                } else {
                    println!("│   ├── {}", label)
                }
            }
        }
    }
    println!();
    Ok(())
}

fn select_entry(pass: &SecVec<u8>, color: bool, entry_type: db::EntryType) -> Result<db::Entry> {
    let catagories = db::get_catagories(pass, &entry_type)?;
    let catagory_idx = lib::get_selection_from_user("Select catagory", false, &catagories, color)?;
    let catagory = catagories[catagory_idx].clone();
    let labels = db::get_labels(pass, &entry_type, Some(&catagory))?;
    let label_idx = lib::get_selection_from_user("Select label", false, &labels, color)?;
    let label = labels[label_idx].clone();
    db::get_entry(pass, label, &entry_type)
}

fn get_user_entry(
    pass: &SecVec<u8>,
    conf: &lib::BlackoutConfig,
    entry_type: db::EntryType,
) -> Result<db::Entry> {
    let labels = db::get_labels(pass, &entry_type, None)?;
    let label = get_input_from_user("Enter label", &labels, true, conf.color)?;
    let mut catagories = db::get_catagories(pass, &entry_type)?;
    catagories.push("Add New".to_string());
    let catagory_idx =
        lib::get_selection_from_user("Choose catagory", true, &catagories, conf.color)?;
    let catagory: String = match catagories[catagory_idx] == "Add New" {
        true => match conf.color {
            true => get_input_from_user("Enter catagory", &catagories, true, conf.color)?,
            false => Input::new().with_prompt("Enter catagory").interact_text()?,
        },
        false => catagories[catagory_idx].clone(),
    };
    let timestamp = lib::get_timestamp();
    let content: String = match entry_type {
        db::EntryType::Note => match Editor::new()
            .executable(&conf.editor)
            .require_save(true)
            .edit("Enter notes")?
        {
            Some(s) => s,
            None => bail!("Error getting note from user"),
        },
        db::EntryType::Totp => match conf.color {
            true => Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter totp URL")
                .validate_with(|input: &String| -> Result<(), String> { sec::validate_totp(input) })
                .interact()?,
            false => Password::new()
                .with_prompt("Enter totp URL")
                .validate_with(|input: &String| -> Result<(), String> { sec::validate_totp(input) })
                .interact()?,
        },
    };
    Ok(db::Entry {
        timestamp,
        label,
        catagory,
        content,
        entry_type: entry_type.clone(),
    })
}

fn get_action(pass: &SecVec<u8>, color: bool) -> Result<Action> {
    let mut actions_str: Vec<String> = vec![];
    let mut actions: Vec<&Action> = vec![];
    let is_empty_notes = db::is_empty(pass, &db::EntryType::Note)?;
    let is_empty_totp = db::is_empty(pass, &db::EntryType::Totp)?;
    let is_empty_backups = lib::get_backups()?.is_empty();
    for a in AVAIL_ACTIONS.iter() {
        if a == &Action::ListLabels && is_empty_totp && is_empty_notes {
            continue;
        }
        if a == &Action::Fetch && is_empty_totp && is_empty_notes {
            continue;
        }
        if a == &Action::Delete && is_empty_totp && is_empty_notes {
            continue;
        }
        if a == &Action::Edit && is_empty_totp && is_empty_notes {
            continue;
        }
        if a == &Action::Export && is_empty_totp && is_empty_notes {
            continue;
        }
        if a == &Action::RestoreBackup && is_empty_backups {
            continue;
        }
        actions_str.push(a.get_str(None).to_string());
        actions.push(a);
    }
    let selection = lib::get_selection_from_user("Choose action", true, &actions_str, color)?;
    Ok(actions[selection].clone())
}

fn get_subaction(pass: &SecVec<u8>, action: Action, color: bool) -> Result<SubAction> {
    if action == Action::Edit || action == Action::Fetch || action == Action::ListLabels {
        let is_empty_notes = db::is_empty(pass, &db::EntryType::Note)?;
        let is_empty_totp = db::is_empty(pass, &db::EntryType::Totp)?;
        if is_empty_notes && is_empty_totp {
            return Err(anyhow!("No entries found"));
        }
        if is_empty_notes {
            return Ok(SubAction::Totp);
        }
        if is_empty_totp {
            return Ok(SubAction::Note);
        }
    }
    match action {
        Action::Add | Action::Delete | Action::Edit | Action::Fetch => {
            let actions_str: Vec<String> = vec![
                action.get_str(Some(SubAction::Note)).to_string(),
                action.get_str(Some(SubAction::Totp)).to_string(),
            ];
            let actions: Vec<SubAction> = vec![SubAction::Note, SubAction::Totp];
            let selection =
                lib::get_selection_from_user("note or totp", true, &actions_str, color)?;
            Ok(actions[selection].clone())
        }
        Action::Export | Action::ListLabels => {
            let actions_str: Vec<String> = vec![
                action.get_str(Some(SubAction::Both)).to_string(),
                action.get_str(Some(SubAction::Note)).to_string(),
                action.get_str(Some(SubAction::Totp)).to_string(),
            ];
            let actions: Vec<SubAction> = vec![SubAction::Both, SubAction::Note, SubAction::Totp];
            let selection =
                lib::get_selection_from_user("notes or totp", true, &actions_str, color)?;
            Ok(actions[selection].clone())
        }
        Action::Generate => {
            let actions_str: Vec<String> = vec![
                action.get_str(Some(SubAction::Password)).to_string(),
                action.get_str(Some(SubAction::Passphrase)).to_string(),
            ];
            let actions: Vec<SubAction> = vec![SubAction::Password, SubAction::Passphrase];
            let selection = lib::get_selection_from_user(
                "Generate password or passphrase",
                true,
                &actions_str,
                color,
            )?;
            Ok(actions[selection].clone())
        }
        _ => Err(anyhow!("Subaction does not exist for action")),
    }
}

fn validate_password_len(input: &str) -> Result<(), String> {
    if input.chars().count() > MIN_PASS_SIZE {
        Ok(())
    } else {
        Err(format!("Password must be longer than {}", MIN_PASS_SIZE))
    }
}

fn validate_label(input: &String, labels: &[String]) -> Result<(), String> {
    if labels.contains(input) {
        Err("Entry already exists".to_string())
    } else {
        Ok(())
    }
}

fn get_input_from_user(
    prompt: &str,
    validation_items: &[String],
    report: bool,
    color: bool,
) -> Result<String> {
    let item: String = match color {
        true => Input::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<(), String> {
                validate_label(input, validation_items)
            })
            .report(report)
            .interact_text()?,
        false => Input::new()
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<(), String> {
                validate_label(input, validation_items)
            })
            .report(report)
            .interact_text()?,
    };
    Ok(item)
}

fn get_len_from_user(prompt: &str, init_txt: &str, color: bool) -> Result<u8> {
    let len: u8 = match color {
        true => Input::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .with_initial_text(init_txt)
            .validate_with(|input: &String| -> Result<(), String> {
                match input.parse::<u8>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid length".to_string()),
                }
            })
            .interact_text()?
            .parse::<u8>()?,
        false => Input::new()
            .with_prompt(prompt)
            .with_initial_text(init_txt)
            .validate_with(|input: &String| -> Result<(), String> {
                match input.parse::<u8>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid length".to_string()),
                }
            })
            .interact_text()?
            .parse::<u8>()?,
    };
    Ok(len)
}

fn generate_password_interactive(conf: &lib::BlackoutConfig) -> Result<()> {
    let (len, selections) = get_password_gen_params(conf.color)?;
    let generated_pass = sec::gen_pass(len, selections);
    let msg = format!("Generated password: {}", generated_pass);
    lib::fmt_print(&msg, lib::ContentType::Password, conf);
    if conf.auto_copy {
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(generated_pass).unwrap();
        lib::fmt_print("Password copied to clipboard", lib::ContentType::Warn, conf);
    }
    Ok(())
}

fn export(pass: &SecVec<u8>, sub_action: SubAction, is_json: bool) -> Result<()> {
    if is_json {
        let j = match sub_action {
            SubAction::Both => {
                let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                json!({
                    "notes": note_entries,
                    "totp": totp_entries
                })
            }
            SubAction::Note => {
                let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                json!({
                    "notes": note_entries,
                })
            }
            SubAction::Totp => {
                let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                json!({
                    "totp": totp_entries,
                })
            }
            _ => bail!("Invalid subaction"),
        };
        let json_str = serde_json::to_string_pretty(&j)?;
        let mut export_file =
            File::create(format!("blackout-export-{}.json", lib::get_timestamp()))?;
        write!(export_file, "{}", json_str)?;
    } else {
        #[derive(Serialize, Deserialize)]
        struct ExportData {
            notes: Vec<db::Entry>,
            totp: Vec<db::Entry>,
        }
        let t = match sub_action {
            SubAction::Both => {
                let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                ExportData {
                    notes: note_entries,
                    totp: totp_entries,
                }
            }
            SubAction::Note => {
                let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                ExportData {
                    notes: note_entries,
                    totp: vec![],
                }
            }
            SubAction::Totp => {
                let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                ExportData {
                    notes: vec![],
                    totp: totp_entries,
                }
            }
            _ => bail!("Invalid subaction"),
        };
        let toml_str = toml::to_string_pretty(&t)?;
        let mut export_file =
            File::create(format!("blackout-export-{}.toml", lib::get_timestamp()))?;
        write!(export_file, "{}", toml_str)?;
    }
    Ok(())
}

fn kill(msg: &str, conf: &lib::BlackoutConfig) -> ! {
    lib::fmt_print(msg, lib::ContentType::Error, conf);
    process::exit(1)
}

fn get_matches() -> ArgMatches {
    Command::new("blackout")
        .about("blackout - Encrypted password/notes and totp manager")
        .version("0.1.0")
        .author("ash")
        .arg_required_else_help(false)
        .arg(
            Arg::new("backup")
                .short('b')
                .long("backup")
                .help("Backup blackout data (saves a snapshot)")
                .action(clap::ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("add")
                .short_flag('A')
                .about("Add note or totp url")
                .subcommand(
                    Command::new("note")
                        .short_flag('N')
                        .about("Add note")
                )
                .subcommand(
                    Command::new("totp")
                        .short_flag('T')
                        .about("Add TOTP url")
                )
        )
        .subcommand(
            Command::new("export")
                .short_flag('E')
                .about("Export note or totp data [Default behavior is to copy the encrypted database to CWD]")
                .arg(
                    Arg::new("json")
                        .short('j')
                        .long("json")
                        .help("Output notes and totp data in json format")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("toml")
                        .short('t')
                        .long("toml")
                        .help("Output notes and totp data in toml format")
                        .action(clap::ArgAction::SetTrue),
                )
        )
        .subcommand(
            Command::new("fetch")
                .short_flag('F')
                .arg_required_else_help(true)
                .about("Fetch notes or totp")
                .subcommand(
                    Command::new("note")
                        .short_flag('N')
                        .about("Fetch note")
                        .arg(
                            Arg::new("label")
                                .help("Note to fetch and display")
                                .value_name("LABEL")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                )
                .subcommand(
                    Command::new("totp")
                        .short_flag('T')
                        .about("Fetch TOTP")
                        .arg(
                            Arg::new("label")
                                .help("totp code to fetch and display")
                                .value_name("LABEL")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                )
        )
        .subcommand(
            Command::new("generate")
                .short_flag('G')
                .about("Generate password/passphrase")
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("pass")
                        .short_flag('W')
                        .about("Generate password")
                        .arg(
                            Arg::new("length")
                                .short('l')
                                .long("length")
                                .help(
                                    "length of password. Interactive allows for more options [DEFAULT: 15]",
                                )
                                .value_name("LENGTH")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                        .arg(
                            Arg::new("interactive")
                                .short('i')
                                .long("interactive")
                                .help("Interractive mode")
                                .required(false)
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("phrase")
                        .short_flag('P')
                        .about("Generate passphrase (BIP-39 word list)")
                        .arg(
                            Arg::new("words")
                                .short('l')
                                .long("length")
                                .help("Number of random words to generate [DEFAULT: 5]")
                                .value_name("NUM_WORDS")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        ),
                )
        )
        .subcommand(
            Command::new("list")
                .short_flag('L')
                .about("List note or totp labels only")
                .subcommand(
                    Command::new("note")
                        .short_flag('N')
                        .about("List note lables")
                )
                .subcommand(
                    Command::new("notes")
                        .about("List note lables")
                )
                .subcommand(
                    Command::new("totp")
                        .short_flag('T')
                        .about("List TOTP labels")
                )
        )
        .get_matches()
}
