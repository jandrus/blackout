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

use std::{env, str::FromStr};

use anyhow::{bail, Result};
use clipboard::{ClipboardContext, ClipboardProvider};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, Editor, Input, MultiSelect, Password, Select};
use secstr::{SecStr, SecVec};
use which::which;

use crate::{conf, db, sec};

pub enum ContentType {
    Body,
    NoteHeader,
    Error,
    Info,
    Password,
    Seed,
    Success,
    TotpHeader,
    Warn,
}

const BANNER: &str = "
__________.__                 __                 __
\\______   \\  | _____    ____ |  | ______  __ ___/  |_
 |    |  _/  | \\__  \\ _/ ___\\|  |/ /  _ \\|  |  \\   __|
 |    |   \\  |__/ __ \\|  \\___|    <  <_> )  |  /|  |
 |______  /____(____  /\\___  >__|_ \\____/|____/ |__|
        \\/          \\/     \\/     \\/
";

pub fn format_seed_phrase(seed: Vec<String>) -> String {
    let mut output = String::from_str("    ").unwrap();
    let mut count = 0;
    for word in seed.iter() {
        let w = format!("{},", word);
        output.push_str(&format!("{:<10}", w));
        count += 1;
        if count % 4 == 0 {
            output.push_str("\n    ");
        }
    }
    output.trim_end().to_owned()
}

pub fn edit_entry(
    pass: &SecVec<u8>,
    entry_type: db::EntryType,
    conf: &conf::BlackoutConfig,
) -> Result<()> {
    let entry_opt = select_entry(pass, conf.color, &entry_type)?;
    if let Some(mut entry) = entry_opt {
        let orig_entry = entry.clone();
        let attr_to_edit = match entry_type {
            db::EntryType::Note => get_selection_from_user(
                "Edit label, category, or note",
                true,
                &[
                    "label".to_owned(),
                    "category".to_owned(),
                    "note".to_owned(),
                    "Go back".to_owned(),
                ],
                conf.color,
            )?,
            db::EntryType::Totp => get_selection_from_user(
                "Edit label, category, or totp url",
                true,
                &[
                    "label".to_owned(),
                    "category".to_owned(),
                    "totp url".to_owned(),
                    "Go back".to_owned(),
                ],
                conf.color,
            )?,
        };
        match attr_to_edit {
            0 => {
                let labels = db::get_labels(pass, &entry_type, None)?;
                let label = get_input_from_user("Enter label", &labels, true, conf.color)?;
                entry.label = label;
            }
            1 => {
                let mut catagories = db::get_catagories(pass, &entry_type)?;
                catagories.push("Add New".to_string());
                let category_idx =
                    get_selection_from_user("Choose category", true, &catagories, conf.color)?;
                let category: String = match catagories[category_idx] == "Add New" {
                    true => match conf.color {
                        true => {
                            get_input_from_user("Enter category", &catagories, true, conf.color)?
                        }
                        false => Input::new().with_prompt("Enter category").interact_text()?,
                    },
                    false => catagories[category_idx].clone(),
                };
                entry.category = category;
            }
            2 => match entry_type {
                db::EntryType::Note => {
                    if let Some(content) = Editor::new()
                        .executable(&conf.editor)
                        .require_save(true)
                        .edit(&entry.content)?
                    {
                        entry.content = content;
                    }
                }
                db::EntryType::Totp => {
                    let content = match conf.color {
                        true => Password::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter totp URL")
                            .validate_with(|input: &String| -> Result<(), String> {
                                sec::validate_totp(input)
                            })
                            .interact()?,
                        false => Password::new()
                            .with_prompt("Enter totp URL")
                            .validate_with(|input: &String| -> Result<(), String> {
                                sec::validate_totp(input)
                            })
                            .interact()?,
                    };
                    entry.content = content;
                }
            },
            _ => return Ok(()),
        }
        db::update_entry(pass, entry, orig_entry)?;
        fmt_print("Update saved", ContentType::Success, conf);
    }
    Ok(())
}

pub fn get_user_password(prompt: &str, color: bool, new: bool) -> Result<SecVec<u8>> {
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

pub fn print_banner(conf: &conf::BlackoutConfig) {
    if conf.banner {
        if conf.color {
            println!("{}", lib::get_rfc().red());
            println!("{}", BANNER.red());
        } else {
            println!("{}", lib::get_rfc());
            println!("{}", BANNER);
        }
    }
}

pub fn list_labels(
    pass: &SecVec<u8>,
    entry_type: db::EntryType,
    conf: &conf::BlackoutConfig,
) -> Result<()> {
    let icon = match entry_type {
        db::EntryType::Note => {
            fmt_print("Available Notes", ContentType::NoteHeader, conf);
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
            fmt_print("Available TOTP Codes", ContentType::TotpHeader, conf);
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
    let catagories = db::get_catagories(pass, &entry_type)?;
    let last_cat = catagories.last().unwrap().clone();
    for category in catagories {
        if category == last_cat {
            if conf.color {
                println!("└── {}", category.blue());
            } else {
                println!("└── {}", category);
            }
            let labels = db::get_labels(pass, &entry_type, Some(&category))?;
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
                println!("├── {}", category.blue());
            } else {
                println!("├── {}", category);
            }
            let labels = db::get_labels(pass, &entry_type, Some(&category))?;
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

pub fn get_user_entry(
    pass: &SecVec<u8>,
    conf: &conf::BlackoutConfig,
    entry_type: db::EntryType,
) -> Result<db::Entry> {
    let labels = db::get_labels(pass, &entry_type, None)?;
    let label = get_input_from_user("Enter label", &labels, true, conf.color)?;
    let mut catagories = db::get_catagories(pass, &entry_type)?;
    catagories.push("Add New".to_string());
    let category_idx = get_selection_from_user("Choose category", true, &catagories, conf.color)?;
    let category: String = match catagories[category_idx] == "Add New" {
        true => match conf.color {
            true => get_input_from_user("Enter category", &catagories, true, conf.color)?,
            false => Input::new().with_prompt("Enter category").interact_text()?,
        },
        false => catagories[category_idx].clone(),
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
        category,
        content,
        entry_type: entry_type.clone(),
    })
}

pub fn get_input_from_user(
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

pub fn get_user_editor(color: bool) -> Result<String> {
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
    Ok(editor)
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

pub fn display_entry(
    entry: db::Entry,
    otp_code: Option<&str>,
    conf: &conf::BlackoutConfig,
) -> Result<()> {
    match entry.entry_type {
        db::EntryType::Note => {
            let header_msg = format!(
                "{} (last updated: {})",
                entry.label,
                lib::get_time_from_ts(entry.timestamp)?
            );
            fmt_print(&header_msg, ContentType::NoteHeader, conf);
            fmt_print(&entry.content, ContentType::Body, conf);
            fmt_print(&entry.label, ContentType::NoteHeader, conf);
        }
        db::EntryType::Totp => {
            let header_msg = format!("TOTP {}", entry.label);
            fmt_print(&header_msg, ContentType::TotpHeader, conf);
            if let Some(code) = otp_code {
                fmt_print(code, ContentType::Body, conf);
            }
            fmt_print(&entry.label, ContentType::TotpHeader, conf);
        }
    }
    println!();
    Ok(())
}

pub fn select_entry(
    pass: &SecVec<u8>,
    color: bool,
    entry_type: &db::EntryType,
) -> Result<Option<db::Entry>> {
    let mut catagories = db::get_catagories(pass, entry_type)?;
    catagories.push("Go back".to_owned());
    let category_idx = get_selection_from_user("Select category", true, &catagories, color)?;
    if category_idx == catagories.len() - 1 {
        return Ok(None);
    }
    let category = catagories[category_idx].clone();
    let mut labels = db::get_labels(pass, entry_type, Some(&category))?;
    labels.push("Go back".to_owned());
    let label_idx = get_selection_from_user("Select label", true, &labels, color)?;
    if label_idx == labels.len() - 1 {
        return Ok(None);
    }
    let label = labels[label_idx].clone();
    let entry = db::get_entry(pass, label, entry_type)?;
    Ok(Some(entry))
}

pub fn copy_to_clipboard(msg: String, conf: &conf::BlackoutConfig) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(msg).unwrap();
    fmt_print(
        "Password/Passphrase copied to clipboard",
        ContentType::Warn,
        conf,
    );
}

pub fn fmt_print(s: &str, content_type: ContentType, conf: &conf::BlackoutConfig) {
    if conf.color {
        match content_type {
            ContentType::Body => println!("{}", s.bold()),
            ContentType::NoteHeader => {
                println!(
                    "{}",
                    lib::stretch_string(" ".to_string(), None)
                        .magenta()
                        .underline()
                );
                if conf.icons {
                    let new_s = format!("{}  {}", "󱞂", s);
                    println!(
                        "{}",
                        lib::stretch_string(new_s.to_string(), Some(3))
                            .magenta()
                            .bold()
                            .underline()
                    );
                } else {
                    println!(
                        "{}",
                        lib::stretch_string(s.to_string(), None)
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
            ContentType::Seed => {
                if conf.icons {
                    println!("\n{}  {}\n", "".cyan(), s.cyan().bold())
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
                    lib::stretch_string(" ".to_string(), None)
                        .cyan()
                        .underline()
                );
                if conf.icons {
                    let new_s = format!("{}  {}", "󰯄", s);
                    println!(
                        "{}",
                        lib::stretch_string(new_s.to_string(), Some(3))
                            .cyan()
                            .bold()
                            .underline()
                    );
                } else {
                    println!(
                        "{}",
                        lib::stretch_string(s.to_string(), None)
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
                println!("{}", lib::stretch_string(" ".to_string(), None).underline());
                println!("{}", lib::stretch_string(s.to_string(), None).underline());
            }
            ContentType::Error => eprintln!("{}", s),
            ContentType::Password => println!("\n{}\n", s),
            _ => println!("{}", s),
        }
    }
}

pub fn get_password_params(color: bool) -> Result<sec::GenerateParams> {
    let length = get_len_from_user("Password length", "15", color)?;
    let options: Vec<(&str, bool)> = vec![
        ("Include numbers", true),
        ("Include lowercase", true),
        ("Include uppercase", true),
        ("Include symbols \"!#$%&()*+,-./<=>?@[]^_{|}~\"", true),
        ("No similar characters \"i, l, 1, L, o, 0, O\"", false),
    ];
    let password_options = match color {
        true => MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Password settings")
            .report(false)
            .items_checked(&options)
            .interact()
            .unwrap()
            .into_iter()
            .map(sec::pass_map_options)
            .collect(),
        false => MultiSelect::new()
            .with_prompt("Password settings")
            .report(false)
            .items_checked(&options)
            .interact()
            .unwrap()
            .into_iter()
            .map(sec::pass_map_options)
            .collect(),
    };
    Ok(sec::GenerateParams {
        password_options,
        length,
    })
}

pub fn get_len_from_user(prompt: &str, init_txt: &str, color: bool) -> Result<u8> {
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

fn validate_password_len(input: &str) -> Result<(), String> {
    if input.chars().count() > lib::MIN_PASS_SIZE {
        Ok(())
    } else {
        Err(format!(
            "Password must be longer than {}",
            lib::MIN_PASS_SIZE
        ))
    }
}

fn validate_label(input: &String, labels: &[String]) -> Result<(), String> {
    if labels.contains(input) {
        Err("Entry already exists".to_string())
    } else {
        Ok(())
    }
}
