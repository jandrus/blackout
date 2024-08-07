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

use std::process;

use colored::Colorize;

mod backup;
mod conf;
mod controller;
mod db;
mod init;
mod sec;
mod ui;

fn main() {
    // INIT
    if let Err(e) = init::setup_file_struct() {
        eprintln!("Error setting up file structure: {}", e);
        process::exit(1);
    }
    // CONF
    let conf = match conf::get_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error getting configuration: {}", e);
            process::exit(1);
        }
    };
    // MATCHES
    let matches = controller::get_matches();
    let (arg_action_opt, mut options) = match controller::parse_args(matches) {
        Ok((a, o)) => (a, o),
        Err(e) => {
            kill(&format!("Error parsing args: {}", e), &conf);
        }
    };
    // PERFORM Action from Args
    if let Some(action) = arg_action_opt {
        if action.is_restricted() {
            if init::initialized() {
                let password = match ui::get_user_password("Unlock blackout", conf.color, false) {
                    Ok(v) => v,
                    Err(e) => kill(&format!("Error getting password: {}", e), &conf),
                };
                let refined_action = match action.refine(Some(&password), conf.color) {
                    Ok(a) => a,
                    Err(e) => kill(&format!("Error refining action: {}", e), &conf),
                };
                if refined_action == controller::Action::Back {
                    process::exit(0);
                }
                match controller::perform_action(
                    &refined_action,
                    &mut options,
                    &conf,
                    Some(&password),
                ) {
                    Ok(_) => process::exit(0),
                    Err(e) => kill(&action.error_msg(e), &conf),
                }
            }
            kill(
                "Blackout has not been initiated (no notes or totp codes exist)",
                &conf,
            );
        }
        let refined_action = match action.refine(None, conf.color) {
            Ok(a) => a,
            Err(e) => kill(&format!("Error refining action: {}", e), &conf),
        };
        if refined_action == controller::Action::Back {
            process::exit(0);
        }
        match controller::perform_action(&refined_action, &mut options, &conf, None) {
            Ok(_) => process::exit(0),
            Err(e) => {
                let msg = action.error_msg(e);
                kill(&msg, &conf);
            }
        }
    }
    // Print banner if necessary
    ui::print_banner(&conf);
    // Initialize DB
    if !init::initialized() {
        if let Err(e) = init::initialize_db(&conf) {
            kill(&format!("Failed to initialize blackout: {}", e), &conf)
        }
    }
    // Edited boolean for autobackups
    let mut has_modified = false;
    // Get password from user
    let password = match ui::get_user_password("Unlock blackout", conf.color, false) {
        Ok(v) => v,
        Err(e) => kill(&format!("Error getting password: {}", e), &conf),
    };
    // Main loop
    loop {
        let mut action = match controller::select_action(&password, conf.color) {
            Ok(a) => a,
            Err(e) => kill(&format!("Failed to get user action: {}", e), &conf),
        };
        if action == controller::Action::Exit {
            break;
        }
        action = match action.refine(Some(&password), conf.color) {
            Ok(a) => a,
            Err(e) => kill(&format!("Failed to get user action: {}", e), &conf),
        };
        if action == controller::Action::Back {
            continue;
        }
        let mut action_options = controller::ActionOptions::default();
        action_options.interractive = true;
        if let Err(e) =
            controller::perform_action(&action, &mut action_options, &conf, Some(&password))
        {
            kill(&action.error_msg(e), &conf)
        }
        if action.is_modifying() {
            has_modified = true;
        }
    }
    if has_modified && conf.autobackup {
        if let Err(e) = backup::create_backup(&conf) {
            kill(&format!("Error creating backup: {}", e), &conf);
        }
    }
    if conf.color {
        println!("{}", "Goodbye".green().bold());
    } else {
        println!("Goodbye");
    }
}

fn kill(msg: &str, conf: &conf::BlackoutConfig) -> ! {
    ui::fmt_print(msg, ui::ContentType::Error, conf);
    process::exit(1)
}
