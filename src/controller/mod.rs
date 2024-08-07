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

use std::io::Write;
use std::{fs, process};

use anyhow::{bail, Error, Result};
use clap::{Arg, ArgMatches, Command};
use secstr::SecVec;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;

use crate::{backup, conf, db, sec, ui};

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Add,
    AddNote,
    AddTotp,
    Back,
    ChangePass,
    CreateBackup,
    Delete,
    DeleteNote,
    DeleteTotp,
    Edit,
    EditNote,
    EditTotp,
    Exit,
    Export,
    ExportBoth,
    ExportNote,
    ExportTotp,
    Fetch,
    FetchNote,
    FetchTotp,
    Generate,
    GenPassphrase,
    GenPassword,
    GenSeedphrase12,
    GenSeedphrase24,
    ListLabels,
    ListBoth,
    ListNotes,
    ListTotps,
    RestoreBackup,
}

impl Action {
    pub fn base_actions() -> Vec<Action> {
        vec![
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
        ]
    }

    pub fn refine(&self, pass_opt: Option<&SecVec<u8>>, color: bool) -> Result<Action> {
        if self.is_basic() {
            return Ok(self.clone());
        }
        if !self.is_refinable() {
            return Ok(self.clone());
        }
        if self.is_dependent() {
            if let Some(pass) = pass_opt {
                let is_empty_notes = db::is_empty(pass, &db::EntryType::Note)?;
                let is_empty_totp = db::is_empty(pass, &db::EntryType::Totp)?;
                if is_empty_notes && is_empty_totp {
                    bail!("No entries found");
                }
                if is_empty_notes {
                    return match self {
                        Action::Delete => Ok(Action::DeleteTotp),
                        Action::Edit => Ok(Action::EditTotp),
                        Action::Export => Ok(Action::ExportTotp),
                        Action::Fetch => Ok(Action::FetchTotp),
                        Action::ListLabels => Ok(Action::ListTotps),
                        _ => unreachable!(),
                    };
                }
                if is_empty_totp {
                    return match self {
                        Action::Delete => Ok(Action::DeleteNote),
                        Action::Edit => Ok(Action::EditNote),
                        Action::Export => Ok(Action::ExportNote),
                        Action::Fetch => Ok(Action::FetchNote),
                        Action::ListLabels => Ok(Action::ListNotes),
                        _ => unreachable!(),
                    };
                }
            }
        }
        let (action_prompts, actions) = match self {
            Action::Add => (
                vec![
                    Action::AddNote.prompt().to_owned(),
                    Action::AddTotp.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![Action::AddNote, Action::AddTotp, Action::Back],
            ),
            Action::Delete => (
                vec![
                    Action::DeleteNote.prompt().to_owned(),
                    Action::DeleteTotp.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![Action::DeleteNote, Action::DeleteTotp, Action::Back],
            ),
            Action::Edit => (
                vec![
                    Action::EditNote.prompt().to_owned(),
                    Action::EditTotp.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![Action::EditNote, Action::EditTotp, Action::Back],
            ),
            Action::Export => (
                vec![
                    Action::ExportNote.prompt().to_owned(),
                    Action::ExportTotp.prompt().to_owned(),
                    Action::ExportBoth.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![
                    Action::ExportNote,
                    Action::ExportTotp,
                    Action::ExportBoth,
                    Action::Back,
                ],
            ),
            Action::Fetch => (
                vec![
                    Action::FetchNote.prompt().to_owned(),
                    Action::FetchTotp.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![Action::FetchNote, Action::FetchTotp, Action::Back],
            ),
            Action::Generate => (
                vec![
                    Action::GenPassphrase.prompt().to_owned(),
                    Action::GenPassword.prompt().to_owned(),
                    Action::GenSeedphrase24.prompt().to_owned(),
                    Action::GenSeedphrase12.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![
                    Action::GenPassphrase,
                    Action::GenPassword,
                    Action::GenSeedphrase24,
                    Action::GenSeedphrase12,
                    Action::Back,
                ],
            ),
            Action::ListLabels => (
                vec![
                    Action::ListNotes.prompt().to_owned(),
                    Action::ListTotps.prompt().to_owned(),
                    Action::ListBoth.prompt().to_owned(),
                    Action::Back.prompt().to_owned(),
                ],
                vec![
                    Action::ListNotes,
                    Action::ListTotps,
                    Action::ListBoth,
                    Action::Back,
                ],
            ),
            _ => unreachable!(),
        };
        let idx = ui::get_selection_from_user(self.prompt(), true, &action_prompts, color)?;
        Ok(actions[idx].clone())
    }

    pub fn prompt(&self) -> &str {
        match self {
            Action::Add => "Add note or totp url",
            Action::AddNote => "Add note",
            Action::AddTotp => "Add totp",
            Action::Back => "Go back",
            Action::ChangePass => "Change master password",
            Action::CreateBackup => "Create backup",
            Action::Delete => "Delete note or totp url",
            Action::DeleteNote => "Delete note",
            Action::DeleteTotp => "Delete totp",
            Action::Edit => "Edit note or totp url",
            Action::EditNote => "Edit note",
            Action::EditTotp => "Edit totp",
            Action::Exit => "Exit",
            Action::Export => "Export notes/totp codes",
            Action::ExportBoth => "Export both",
            Action::ExportNote => "Export notes",
            Action::ExportTotp => "Export totp urls",
            Action::Fetch => "Fetch note or totp code",
            Action::FetchNote => "Fetch note",
            Action::FetchTotp => "Fetch totp",
            Action::Generate => "Generate password, passphrase, or seed phrase",
            Action::GenPassphrase => "Generate passphrase",
            Action::GenPassword => "Generate password",
            Action::GenSeedphrase12 => "Generate 12 word seed phrase",
            Action::GenSeedphrase24 => "Generate 24 word seed phrase",
            Action::ListLabels => "List note or totp labels",
            Action::ListBoth => "List both",
            Action::ListNotes => "List note labels",
            Action::ListTotps => "List totp labels",
            Action::RestoreBackup => "Restore backup",
        }
    }

    pub fn error_msg(&self, e: Error) -> String {
        match self {
            Action::AddNote => format!("Failed to add note: {}", e),
            Action::AddTotp => format!("Failed to add totp code: {}", e),
            Action::ChangePass => format!("Failed to change master password: {}", e),
            Action::CreateBackup => format!("Failed to create backup: {}", e),
            Action::DeleteNote => format!("Failed to delete note: {}", e),
            Action::DeleteTotp => format!("Failed to delete totp url: {}", e),
            Action::EditNote => format!("Failed to edit note: {}", e),
            Action::EditTotp => format!("Failed to edit totp url: {}", e),
            Action::ExportBoth | Action::ExportNote | Action::ExportTotp => {
                format!("Failed to export data: {}", e)
            }
            Action::FetchNote => format!("Failed to fetch note: {}", e),
            Action::FetchTotp => format!("Failed to fetch totp code: {}", e),
            Action::GenPassphrase => format!("Failed to generate passphrase: {}", e),
            Action::GenPassword => format!("Failed to generate password: {}", e),
            Action::GenSeedphrase12 | Action::GenSeedphrase24 => {
                format!("Failed to generate seed phrase: {}", e)
            }
            Action::ListBoth => format!("Failed to list notes and totp entries: {}", e),
            Action::ListNotes => format!("Failed to list note entries: {}", e),
            Action::ListTotps => format!("Failed to list totp entries: {}", e),
            Action::RestoreBackup => format!("Failed to restore backup: {}", e),
            _ => format!("Unknown error: {}", e),
        }
    }

    pub fn is_modifying(&self) -> bool {
        matches!(
            self,
            Action::AddNote
                | Action::AddTotp
                | Action::DeleteNote
                | Action::DeleteTotp
                | Action::EditNote
                | Action::EditTotp
        )
    }

    pub fn is_dependent(&self) -> bool {
        matches!(
            self,
            Action::Delete | Action::Edit | Action::Export | Action::Fetch | Action::ListLabels
        )
    }

    pub fn is_restricted(&self) -> bool {
        !matches!(
            self,
            Action::Back
                | Action::ChangePass
                | Action::CreateBackup
                | Action::Exit
                | Action::GenPassphrase
                | Action::GenPassword
                | Action::GenSeedphrase12
                | Action::GenSeedphrase24
                | Action::Generate
        )
    }

    pub fn is_basic(&self) -> bool {
        matches!(
            self,
            Action::ChangePass | Action::CreateBackup | Action::RestoreBackup | Action::Exit
        )
    }

    pub fn is_refinable(&self) -> bool {
        matches!(
            self,
            Action::Add
                | Action::Delete
                | Action::Edit
                | Action::Export
                | Action::Fetch
                | Action::Generate
                | Action::ListLabels
        )
    }
}

#[derive(Clone, Debug)]
pub enum ExportFormat {
    Db,
    Json,
    Toml,
}

#[derive(Clone, Debug)]
pub struct ActionOptions {
    pub export_format: ExportFormat,
    pub interractive: bool,
    pub label_opt: Option<String>,
    pub generate_params: sec::GenerateParams,
}

impl ActionOptions {
    pub fn default() -> Self {
        ActionOptions {
            export_format: ExportFormat::Db,
            interractive: false,
            label_opt: None,
            generate_params: sec::GenerateParams {
                password_options: vec![
                    sec::PasswordOptions::AlphaLower,
                    sec::PasswordOptions::AlphaUpper,
                    sec::PasswordOptions::Nums,
                    sec::PasswordOptions::Symbols,
                ],
                length: 15,
            },
        }
    }
}

pub fn select_action(pass: &SecVec<u8>, color: bool) -> Result<Action> {
    let mut action_prompts: Vec<String> = vec![];
    let mut actions: Vec<Action> = vec![];
    let is_empty_notes = db::is_empty(pass, &db::EntryType::Note)?;
    let is_empty_totp = db::is_empty(pass, &db::EntryType::Totp)?;
    let is_empty_backups = backup::get_backups()?.is_empty();
    for a in Action::base_actions().iter() {
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
        action_prompts.push(a.prompt().to_string());
        actions.push(a.clone());
    }
    let selection = ui::get_selection_from_user("Choose action", true, &action_prompts, color)?;
    Ok(actions[selection].clone())
}

pub fn perform_action(
    action: &Action,
    options: &mut ActionOptions,
    conf: &conf::BlackoutConfig,
    password: Option<&SecVec<u8>>,
) -> Result<()> {
    match action {
        Action::AddNote => {
            if let Some(pass) = password {
                let entry = ui::get_user_entry(pass, conf, db::EntryType::Note)?;
                db::add_entry(pass, entry)?;
                ui::fmt_print("Note added", ui::ContentType::Success, conf);
            }
        }
        Action::AddTotp => {
            if let Some(pass) = password {
                let entry = ui::get_user_entry(pass, conf, db::EntryType::Totp)?;
                db::add_entry(pass, entry)?;
                ui::fmt_print("Totp added", ui::ContentType::Success, conf);
            }
        }
        Action::ChangePass => {
            ui::fmt_print(
                "WARNING: Changing blackout password.",
                ui::ContentType::Warn,
                conf,
            );
            let confirm =
                ui::confirm_with_user("Are you sure you want to continue?", false, conf.color)?;
            if confirm {
                let current_pass =
                    ui::get_user_password("Enter CURRENT password", conf.color, false)?;
                let new_pass = ui::get_user_password("Enter NEW password", conf.color, true)?;
                db::rekey(&current_pass, &new_pass)?;
                ui::fmt_print(
                    "Password updated successfully",
                    ui::ContentType::Success,
                    conf,
                );
                process::exit(0);
            }
        }
        Action::CreateBackup => backup::create_backup(conf)?,
        Action::DeleteNote => {
            if let Some(pass) = password {
                delete_entry(pass, conf, true)?;
            }
        }
        Action::DeleteTotp => {
            if let Some(pass) = password {
                delete_entry(pass, conf, false)?;
            }
        }
        Action::EditNote => {
            if let Some(pass) = password {
                ui::edit_entry(pass, db::EntryType::Note, conf)?;
            }
        }
        Action::EditTotp => {
            if let Some(pass) = password {
                ui::edit_entry(pass, db::EntryType::Totp, conf)?;
            }
        }
        Action::ExportBoth | Action::ExportNote | Action::ExportTotp => {
            if let Some(pass) = password {
                if options.interractive {
                    let selection = ui::get_selection_from_user(
                        "file type output",
                        true,
                        &[
                            "json".to_owned(),
                            "toml".to_owned(),
                            "database (data remains encrypted). Use this to migrate to new machine."
                                .to_owned(),
                            "Go back".to_owned(),
                        ],
                        conf.color,
                    )?;
                    match selection {
                        0 => options.export_format = ExportFormat::Json,
                        1 => options.export_format = ExportFormat::Toml,
                        2 => options.export_format = ExportFormat::Db,
                        3 => return Ok(()),
                        _ => unreachable!(),
                    }
                }
                export(action, pass, options.export_format.clone(), conf)?;
            }
        }
        Action::FetchNote => {
            if let Some(pass) = password {
                if db::is_empty(pass, &db::EntryType::Note)? {
                    bail!("No notes found");
                }
                let entry_opt = match options.interractive {
                    true => ui::select_entry(pass, conf.color, &db::EntryType::Note)?,
                    false => match &options.label_opt {
                        Some(s) => Some(db::get_entry(pass, s.to_string(), &db::EntryType::Note)?),
                        None => bail!("label not privided"),
                    },
                };
                if let Some(entry) = entry_opt {
                    ui::display_entry(entry, None, conf)?;
                }
            }
        }
        Action::FetchTotp => {
            if let Some(pass) = password {
                if db::is_empty(pass, &db::EntryType::Totp)? {
                    bail!("No totp found");
                }
                let entry_opt = match options.interractive {
                    true => ui::select_entry(pass, conf.color, &db::EntryType::Totp)?,
                    false => match &options.label_opt {
                        Some(s) => Some(db::get_entry(pass, s.to_string(), &db::EntryType::Totp)?),
                        None => bail!("label not privided"),
                    },
                };
                if let Some(entry) = entry_opt {
                    let otp_code = sec::totp_code(&entry.content)?;
                    ui::display_entry(entry, Some(&otp_code), conf)?;
                }
            }
        }
        Action::GenPassphrase => {
            if options.interractive {
                options.generate_params.length =
                    ui::get_len_from_user("Number of words", "5", conf.color)?;
            }
            let phrase = sec::gen_passphrase(options.generate_params.length)?;
            let msg = format!("Generated passphrase: {}", phrase);
            ui::fmt_print(&msg, ui::ContentType::Password, conf);
            if conf.auto_copy {
                ui::copy_to_clipboard(phrase, conf);
            }
        }
        Action::GenPassword => {
            if options.interractive {
                options.generate_params = ui::get_password_params(conf.color)?;
            }
            let pass = sec::gen_pass(options.generate_params.clone());
            let msg = format!("Generated password: {}", pass);
            ui::fmt_print(&msg, ui::ContentType::Password, conf);
            if conf.auto_copy {
                ui::copy_to_clipboard(pass, conf);
            }
        }
        Action::GenSeedphrase12 => {
            let seed = sec::gen_seedphrase(12)?;
            let msg = format!("Generated seed phrase:\n{}", ui::format_seed_phrase(seed));
            ui::fmt_print(&msg, ui::ContentType::Seed, conf);
        }
        Action::GenSeedphrase24 => {
            let seed = sec::gen_seedphrase(24)?;
            let msg = format!("Generated seed phrase:\n{}", ui::format_seed_phrase(seed));
            ui::fmt_print(&msg, ui::ContentType::Seed, conf);
        }
        Action::ListBoth => {
            if let Some(pass) = password {
                if !db::is_empty(pass, &db::EntryType::Note)? {
                    ui::list_labels(pass, db::EntryType::Note, conf)?;
                }
                if !db::is_empty(pass, &db::EntryType::Totp)? {
                    ui::list_labels(pass, db::EntryType::Totp, conf)?;
                }
            }
        }
        Action::ListNotes => {
            if let Some(pass) = password {
                if !db::is_empty(pass, &db::EntryType::Note)? {
                    ui::list_labels(pass, db::EntryType::Note, conf)?;
                }
            }
        }
        Action::ListTotps => {
            if let Some(pass) = password {
                if !db::is_empty(pass, &db::EntryType::Totp)? {
                    ui::list_labels(pass, db::EntryType::Totp, conf)?;
                }
            }
        }
        Action::RestoreBackup => backup::restore_backup(conf)?,
        _ => unreachable!("Invalid Action"),
    }
    Ok(())
}

pub fn parse_args(matches: ArgMatches) -> Result<(Option<Action>, ActionOptions)> {
    let mut options = ActionOptions::default();
    if matches.get_flag("backup") {
        return Ok((Some(Action::CreateBackup), options));
    }
    if matches.get_flag("changepass") {
        return Ok((Some(Action::ChangePass), options));
    }
    if matches.get_flag("restore") {
        return Ok((Some(Action::RestoreBackup), options));
    }
    let action = match matches.subcommand() {
        // Matches -> add
        Some(("add", add_matches)) => match add_matches.subcommand() {
            Some(("note", _)) => Action::AddNote,
            Some(("totp", _)) => Action::AddTotp,
            _ => {
                options.interractive = true;
                Action::Add
            }
        },
        // Matches -> Delete
        Some(("delete", del_matches)) => match del_matches.subcommand() {
            // Matches -> delete -> note
            Some(("note", del_note_matches)) => {
                match del_note_matches.contains_id("label") {
                    true => {
                        let label = del_note_matches
                            .get_one::<String>("label")
                            .unwrap()
                            .to_string();
                        options.label_opt = Some(label);
                    }
                    false => options.interractive = true,
                }
                Action::DeleteNote
            }
            // Matches -> delete -> totp
            Some(("totp", del_totp_matches)) => {
                match del_totp_matches.contains_id("label") {
                    true => {
                        let label = del_totp_matches
                            .get_one::<String>("label")
                            .unwrap()
                            .to_string();
                        options.label_opt = Some(label);
                    }
                    false => options.interractive = true,
                }
                Action::DeleteTotp
            }
            _ => {
                options.interractive = true;
                Action::Delete
            }
        },
        // Matches -> Edit
        Some(("edit", edit_matches)) => match edit_matches.subcommand() {
            // Matches -> edit -> note
            Some(("note", edit_note_matches)) => {
                match edit_note_matches.contains_id("label") {
                    true => {
                        let label = edit_note_matches
                            .get_one::<String>("label")
                            .unwrap()
                            .to_string();
                        options.label_opt = Some(label);
                    }
                    false => options.interractive = true,
                }
                Action::EditNote
            }
            // Matches -> edit -> totp
            Some(("totp", edit_totp_matches)) => {
                match edit_totp_matches.contains_id("label") {
                    true => {
                        let label = edit_totp_matches
                            .get_one::<String>("label")
                            .unwrap()
                            .to_string();
                        options.label_opt = Some(label);
                    }
                    false => options.interractive = true,
                }
                Action::EditTotp
            }
            _ => {
                options.interractive = true;
                Action::Edit
            }
        },
        // Matches -> export
        Some(("export", export_matches)) => match export_matches.subcommand() {
            // Matches -> export -> both
            Some(("both", export_both_matches)) => {
                if export_both_matches.get_flag("json") {
                    options.export_format = ExportFormat::Json;
                } else if export_both_matches.get_flag("toml") {
                    options.export_format = ExportFormat::Toml;
                } else {
                    options.interractive = true;
                }
                Action::ExportBoth
            }
            // Matches -> export -> note
            Some(("notes", export_note_matches)) => {
                if export_note_matches.get_flag("json") {
                    options.export_format = ExportFormat::Json;
                } else if export_note_matches.get_flag("toml") {
                    options.export_format = ExportFormat::Toml;
                } else {
                    options.interractive = true;
                }
                Action::ExportNote
            }
            // Matches -> export -> totp
            Some(("totps", export_totp_matches)) => {
                if export_totp_matches.get_flag("json") {
                    options.export_format = ExportFormat::Json;
                } else if export_totp_matches.get_flag("toml") {
                    options.export_format = ExportFormat::Toml;
                } else {
                    options.interractive = true;
                }
                Action::ExportTotp
            }
            _ => {
                options.interractive = true;
                Action::Export
            }
        },
        // Matches -> fetch
        Some(("fetch", fetch_matches)) => match fetch_matches.subcommand() {
            // Matches -> fetch -> note
            Some(("note", fetch_note_matches)) => {
                match fetch_note_matches.contains_id("label") {
                    true => {
                        let label = fetch_note_matches
                            .get_one::<String>("label")
                            .unwrap()
                            .to_string();
                        options.label_opt = Some(label);
                    }
                    false => options.interractive = true,
                }
                Action::FetchNote
            }
            // Matches -> fetch -> totp
            Some(("totp", fetch_totp_matches)) => {
                match fetch_totp_matches.contains_id("label") {
                    true => {
                        let label = fetch_totp_matches
                            .get_one::<String>("label")
                            .unwrap()
                            .to_string();
                        options.label_opt = Some(label);
                    }
                    false => options.interractive = true,
                }
                Action::FetchTotp
            }
            _ => {
                options.interractive = true;
                Action::Fetch
            }
        },
        // Matches -> generate
        Some(("generate", gen_matches)) => match gen_matches.subcommand() {
            // Matches -> generate -> pass
            Some(("pass", gen_pass_matches)) => {
                if gen_pass_matches.get_flag("interactive") {
                    options.interractive = true;
                }
                if gen_pass_matches.contains_id("length") {
                    let len: u8 = gen_pass_matches
                        .get_one::<String>("length")
                        .unwrap()
                        .to_string()
                        .parse::<u8>()?;
                    options.generate_params.length = len;
                }
                Action::GenPassword
            }
            // Matches -> generate -> phrase
            Some(("phrase", gen_phrase_matches)) => {
                options.generate_params.length = 5;
                if gen_phrase_matches.contains_id("words") {
                    let len: u8 = gen_phrase_matches
                        .get_one::<String>("words")
                        .unwrap()
                        .to_string()
                        .parse::<u8>()?;
                    options.generate_params.length = len;
                }
                Action::GenPassphrase
            }
            // Matches -> generate -> seed
            Some(("seed", _)) => {
                options.generate_params.length = 24;
                Action::GenSeedphrase24
            }
            _ => {
                options.interractive = true;
                Action::Generate
            }
        },
        // Matches -> list
        Some(("list", list_matches)) => match list_matches.subcommand() {
            Some(("notes", _)) => Action::ListNotes,
            Some(("totps", _)) => Action::ListTotps,
            _ => Action::ListBoth,
        },
        _ => return Ok((None, options)),
    };
    Ok((Some(action), options))
}

pub fn get_matches() -> ArgMatches {
    Command::new("blackout")
        .about("blackout - Encrypted password/notes and totp manager")
        .version("1.0.0")
        .author("ash")
        .arg_required_else_help(false)
        .arg(
            Arg::new("backup")
                .short('b')
                .long("backup")
                .help("Backup blackout data (saves a snapshot)")
                .exclusive(true)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("changepass")
                .short('c')
                .long("changepass")
                .help("Change master blackout password")
                .exclusive(true)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("restore")
                .short('r')
                .long("restore")
                .help("Restore blackout backup")
                .exclusive(true)
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
            Command::new("delete")
                .short_flag('D')
                .about("Delete note or totp url")
                .subcommand(
                    Command::new("note")
                        .short_flag('N')
                        .about("Delete note")
                        .arg(
                            Arg::new("label")
                                .help("Note to delete")
                                .value_name("LABEL")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                )
                .subcommand(
                    Command::new("totp")
                        .short_flag('T')
                        .about("Delete totp")
                        .arg(
                            Arg::new("label")
                                .help("Totp to delete")
                                .value_name("LABEL")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                )
        )
        .subcommand(
            Command::new("edit")
                .short_flag('E')
                .about("Edit note or totp url")
                .subcommand(
                    Command::new("note")
                        .short_flag('N')
                        .about("Edit note")
                        .arg(
                            Arg::new("label")
                                .help("Note to edit")
                                .value_name("LABEL")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                )
                .subcommand(
                    Command::new("totp")
                        .short_flag('T')
                        .about("Edit totp url")
                        .arg(
                            Arg::new("label")
                                .help("Totp to edit")
                                .value_name("LABEL")
                                .required(false)
                                .action(clap::ArgAction::Set)
                                .num_args(1),
                        )
                )
        )
        .subcommand(
            Command::new("export")
                .short_flag('X')
                .about("Export note or totp urls")
                .subcommand(
                    Command::new("both")
                        .short_flag('B')
                        .about("Export notes and totp url")
                        .arg(
                            Arg::new("json")
                                .short('j')
                                .long("json")
                                .help("Output data in json format")
                                .exclusive(true)
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("toml")
                                .short('t')
                                .long("toml")
                                .help("Output data in toml format")
                                .exclusive(true)
                                .action(clap::ArgAction::SetTrue),
                        )
                )
                .subcommand(
                    Command::new("notes")
                        .short_flag('N')
                        .about("Export notes")
                        .alias("note")
                        .arg(
                            Arg::new("json")
                                .short('j')
                                .long("json")
                                .help("Output notes in json format")
                                .exclusive(true)
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("toml")
                                .short('t')
                                .long("toml")
                                .help("Output notes in toml format")
                                .exclusive(true)
                                .action(clap::ArgAction::SetTrue),
                        )
                )
                .subcommand(
                    Command::new("totps")
                        .short_flag('T')
                        .about("Export totp urls")
                        .alias("totp")
                        .arg(
                            Arg::new("json")
                                .short('j')
                                .long("json")
                                .help("Output totp data in json format")
                                .exclusive(true)
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("toml")
                                .short('t')
                                .long("toml")
                                .help("Output totp data in toml format")
                                .exclusive(true)
                                .action(clap::ArgAction::SetTrue),
                        )
                )
        )
        .subcommand(
            Command::new("fetch")
                .short_flag('F')
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
                .alias("gen")
                .about("Generate password, passphrase, or seed phrase")
                .subcommand(
                    Command::new("pass")
                        .short_flag('W')
                        .about("Generate password")
                        .arg(
                            Arg::new("length")
                                .short('l')
                                .long("length")
                                .help("length of password. Interactive allows for more options [DEFAULT: 15]")
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
                .subcommand(
                    Command::new("seed")
                        .short_flag('S')
                        .about("Generate 24 word seed phrase (BIP-39 word list)")
                )
        )
        .subcommand(
            Command::new("list")
                .short_flag('L')
                .about("List note or totp labels only")
                .subcommand(
                    Command::new("notes")
                        .short_flag('N')
                        .alias("note")
                        .about("List note lables")
                )
                .subcommand(
                    Command::new("totps")
                        .short_flag('T')
                        .alias("totp")
                        .about("List TOTP labels")
                )
        )
        .get_matches()
}

fn export(
    action: &Action,
    pass: &SecVec<u8>,
    format: ExportFormat,
    conf: &conf::BlackoutConfig,
) -> Result<()> {
    match format {
        ExportFormat::Db => {
            if let Err(e) = fs::copy(lib::get_project_file(lib::ProjFiles::Data)?, "blackout.db") {
                bail!("Error exporting database: {}", e);
            };
        }
        ExportFormat::Json => {
            ui::fmt_print(
                "WARNING: this will output all of your data in CLEAR TEXT",
                ui::ContentType::Warn,
                conf,
            );
            if ui::confirm_with_user("Are you sure", false, conf.color)? {
                let json_data = match action {
                    Action::ExportBoth => {
                        let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                        let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                        json!({
                            "notes": note_entries,
                            "totp": totp_entries
                        })
                    }
                    Action::ExportNote => {
                        let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                        json!({
                            "notes": note_entries,
                        })
                    }
                    Action::ExportTotp => {
                        let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                        json!({
                            "totp": totp_entries,
                        })
                    }
                    _ => bail!("Invalid subaction"),
                };
                let json_str = serde_json::to_string_pretty(&json_data)?;
                let mut export_file =
                    fs::File::create(format!("blackout-export-{}.json", lib::get_timestamp()))?;
                write!(export_file, "{}", json_str)?;
            }
        }
        ExportFormat::Toml => {
            #[derive(Serialize, Deserialize)]
            struct ExportData {
                notes: Vec<db::Entry>,
                totp: Vec<db::Entry>,
            }
            let toml_data = match action {
                Action::ExportBoth => {
                    let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                    let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                    ExportData {
                        notes: note_entries,
                        totp: totp_entries,
                    }
                }
                Action::ExportNote => {
                    let note_entries = db::get_entries(pass, &db::EntryType::Note)?;
                    ExportData {
                        notes: note_entries,
                        totp: vec![],
                    }
                }
                Action::ExportTotp => {
                    let totp_entries = db::get_entries(pass, &db::EntryType::Totp)?;
                    ExportData {
                        notes: vec![],
                        totp: totp_entries,
                    }
                }
                _ => bail!("Invalid subaction"),
            };
            let toml_str = toml::to_string_pretty(&toml_data)?;
            let mut export_file =
                fs::File::create(format!("blackout-export-{}.toml", lib::get_timestamp()))?;
            write!(export_file, "{}", toml_str)?;
        }
    }
    Ok(())
}

fn delete_entry(pass: &SecVec<u8>, conf: &conf::BlackoutConfig, is_note: bool) -> Result<()> {
    let entry_opt = match is_note {
        true => ui::select_entry(pass, conf.color, &db::EntryType::Note)?,
        false => ui::select_entry(pass, conf.color, &db::EntryType::Totp)?,
    };
    if let Some(entry) = entry_opt {
        ui::fmt_print(
            "WARNING ACTION IS IRREVERSIBLE (backup is recommended)",
            ui::ContentType::Warn,
            conf,
        );
        let msg = match is_note {
            true => format!("Are you sure you want to delete the note {}", entry.label),
            false => format!(
                "Are you sure you want to delete the totp url {}",
                entry.label
            ),
        };
        let confirm = ui::confirm_with_user(&msg, false, conf.color)?;
        if confirm {
            db::delete_entry(pass, &entry)?;
            ui::fmt_print(
                &format!("DELETED {}", &entry.label),
                ui::ContentType::Warn,
                conf,
            );
        }
    }
    Ok(())
}
