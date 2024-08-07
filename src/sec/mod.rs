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

use anyhow::{anyhow, Result};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use totp_rs::TOTP;

#[derive(Clone, Debug)]
pub struct GenerateParams {
    pub password_options: Vec<PasswordOptions>,
    pub length: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PasswordOptions {
    AlphaLower,
    AlphaUpper,
    Nums,
    Symbols,
    NoSimilar,
    None,
}

const ALPHA_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHA_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&()*+,-./<=>?@[]^_{|}~";
const SIMILAR_CHARS: &[u8] = b"il1oO0";

pub fn gen_seedphrase(num_words: u8) -> Result<Vec<String>> {
    let wl = get_words()?;
    let mut rng = get_rng();
    let mut seed: Vec<String> = vec![];
    (0..num_words).for_each(|_| {
        let idx = rng.gen_range(0..wl.len());
        seed.push(wl[idx].clone());
    });
    Ok(seed)
}

pub fn gen_passphrase(num_words: u8) -> Result<String> {
    let wl = get_words()?;
    let mut rng = get_rng();
    let mut passphrase = String::new();
    (0..num_words).for_each(|_| {
        let idx = rng.gen_range(0..wl.len());
        passphrase.push_str(wl[idx].as_str());
    });
    Ok(passphrase)
}

pub fn totp_code(otp: &str) -> Result<String> {
    let totp = TOTP::from_url_unchecked(otp)?;
    match totp.generate_current() {
        Ok(s) => Ok(s),
        Err(e) => Err(anyhow!(e.to_string())),
    }
}

pub fn validate_totp(otp: &str) -> Result<(), String> {
    if otp.is_empty() {
        return Ok(());
    }
    match TOTP::from_url_unchecked(otp) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Invalid TOTP: {}", e)),
    }
}

pub fn gen_pass(gen_params: GenerateParams) -> String {
    let mut char_vec: Vec<u8> = vec![];
    if gen_params.password_options.contains(&PasswordOptions::Nums) {
        char_vec.append(&mut NUMS.to_owned());
    }
    if gen_params
        .password_options
        .contains(&PasswordOptions::AlphaLower)
    {
        char_vec.append(&mut ALPHA_LOWER.to_owned());
    }
    if gen_params
        .password_options
        .contains(&PasswordOptions::AlphaUpper)
    {
        char_vec.append(&mut ALPHA_UPPER.to_owned());
    }
    if gen_params
        .password_options
        .contains(&PasswordOptions::NoSimilar)
    {
        for c in SIMILAR_CHARS {
            char_vec.retain(|x| x != c);
        }
    }
    if gen_params
        .password_options
        .contains(&PasswordOptions::Symbols)
    {
        char_vec.append(&mut SYMBOLS.to_owned());
    }
    let mut rng = get_rng();
    (0..gen_params.length)
        .map(|_| {
            let idx = rng.gen_range(0..char_vec.len());
            char_vec[idx] as char
        })
        .collect()
}

pub fn pass_map_options(i: usize) -> PasswordOptions {
    match i {
        0 => PasswordOptions::Nums,
        1 => PasswordOptions::AlphaLower,
        2 => PasswordOptions::AlphaUpper,
        3 => PasswordOptions::Symbols,
        4 => PasswordOptions::NoSimilar,
        _ => PasswordOptions::None,
    }
}

fn get_words() -> Result<Vec<String>> {
    let wl_file_str = lib::get_project_file(lib::ProjFiles::WordList)?;
    let wl_str = lib::read_file(&wl_file_str)?;
    let wl: Vec<String> = wl_str.split('\n').map(|s| s.to_string()).collect();
    Ok(wl)
}

fn get_rng() -> ChaCha20Rng {
    let mut seed: <ChaCha20Rng as SeedableRng>::Seed = Default::default();
    rand::thread_rng().fill(&mut seed);
    ChaCha20Rng::from_seed(seed)
}
