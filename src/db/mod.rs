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

use std::str::from_utf8;

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use secstr::{SecStr, SecVec};
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub timestamp: i64,
    pub label: String,
    pub catagory: String,
    pub content: String,
    pub entry_type: EntryType,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum EntryType {
    Note,
    Totp,
}

impl EntryType {
    fn table(&self) -> &str {
        match self {
            EntryType::Note => "Notes",
            EntryType::Totp => "Totp",
        }
    }
}

pub fn get_entries(pass: &SecVec<u8>, entry_type: &EntryType) -> Result<Vec<Entry>> {
    let conn = connect_db(pass)?;
    let mut stmt = conn.prepare(&format!("SELECT * FROM {}", entry_type.table(),))?;
    let rows = stmt.query_map([], |row| {
        let timestamp: i64 = row.get(0)?;
        let label: String = row.get(1)?;
        let catagory: String = row.get(2)?;
        let content: String = row.get(3)?;
        Ok(Entry {
            timestamp,
            label,
            catagory,
            content,
            entry_type: entry_type.clone(),
        })
    })?;
    let mut entries: Vec<Entry> = vec![];
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

pub fn is_empty(pass: &SecVec<u8>, entry_type: &EntryType) -> Result<bool> {
    let conn = connect_db(pass)?;
    let stmt_str = format!("SELECT COUNT(*) FROM {}", entry_type.table());
    let mut stmt = conn.prepare(&stmt_str)?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(r) => {
            let count: i64 = r.get(0)?;
            Ok(count == 0)
        }
        None => Ok(false),
    }
}

pub fn init(pass: &SecVec<u8>) -> Result<()> {
    let conn = connect_db(pass)?;
    conn.execute(&format!("CREATE TABLE IF NOT EXISTS {} (timestamp INTEGER, label TEXT UNIQUE, catagory TEXT, content TEXT)", EntryType::Note.table()), ())?;
    conn.execute(&format!("CREATE TABLE IF NOT EXISTS {} (timestamp INTEGER, label TEXT UNIQUE, catagory TEXT, content TEXT)", EntryType::Totp.table()), ())?;
    Ok(())
}

pub fn validate_password_with_db(raw_pass: &str) -> Result<(), String> {
    let pass = SecStr::from(raw_pass);
    let conn = match connect_db(&pass) {
        Ok(c) => c,
        Err(e) => return Err(e.to_string()),
    };
    if conn.prepare("SELECT count(*) FROM sqlite_master").is_ok() {
        return Ok(());
    };
    Err("Wrong password".to_string())
}

pub fn add_entry(pass: &SecVec<u8>, entry: Entry) -> Result<()> {
    let conn = connect_db(pass)?;
    let stmt = format!(
        "INSERT INTO {} (timestamp, label, catagory, content) VALUES (?1, ?2, ?3, ?4)",
        entry.entry_type.table()
    );
    conn.execute(
        &stmt,
        (entry.timestamp, entry.label, entry.catagory, entry.content),
    )?;
    Ok(())
}

pub fn get_entry(pass: &SecVec<u8>, label: String, entry_type: &EntryType) -> Result<Entry> {
    let conn = connect_db(pass)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT * FROM {} WHERE label='{}'",
        entry_type.table(),
        label
    ))?;
    let rows = stmt.query_map([], |row| {
        let timestamp: i64 = row.get(0)?;
        let label: String = row.get(1)?;
        let catagory: String = row.get(2)?;
        let content: String = row.get(3)?;
        Ok(Entry {
            timestamp,
            label,
            catagory,
            content,
            entry_type: entry_type.clone(),
        })
    })?;
    match rows.last() {
        Some(ent) => Ok(ent?),
        None => Err(anyhow!("Entry not found")),
    }
}

pub fn get_catagories(pass: &SecVec<u8>, entry_type: &EntryType) -> Result<Vec<String>> {
    let mut catagories: Vec<String> = vec![];
    let conn = connect_db(pass)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT catagory FROM {}",
        entry_type.table()
    ))?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        Ok(name)
    })?;
    for row in rows.into_iter() {
        catagories.push(row?);
    }
    catagories.sort();
    Ok(catagories)
}

pub fn get_labels(
    pass: &SecVec<u8>,
    entry_type: &EntryType,
    catagory: Option<&str>,
) -> Result<Vec<String>> {
    let mut labels: Vec<String> = vec![];
    let conn = connect_db(pass)?;
    let stmt_str = match catagory {
        Some(s) => format!(
            "SELECT label FROM {} WHERE catagory='{}'",
            entry_type.table(),
            s
        ),
        None => format!("SELECT label FROM {}", entry_type.table()),
    };
    let mut stmt = conn.prepare(&stmt_str)?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        Ok(name)
    })?;
    for row in rows {
        labels.push(row?);
    }
    labels.sort();
    Ok(labels)
}

pub fn update_entry(pass: &SecVec<u8>, entry: Entry, orig_entry: Entry) -> Result<()> {
    let timestamp = lib::get_timestamp();
    let conn = connect_db(pass)?;
    if entry.content != orig_entry.content {
        let stmt_str = format!(
            "UPDATE {} SET timestamp='{}',content='{}' WHERE label='{}'",
            entry.entry_type.table(),
            timestamp,
            entry.content,
            entry.label
        );
        conn.execute(&stmt_str, [])?;
    }
    if entry.catagory != orig_entry.catagory {
        let stmt_str = format!(
            "UPDATE {} SET timestamp='{}',catagory='{}' WHERE label='{}'",
            entry.entry_type.table(),
            timestamp,
            entry.catagory,
            entry.label
        );
        conn.execute(&stmt_str, [])?;
    }
    if entry.label != orig_entry.label {
        let stmt_str = format!(
            "UPDATE {} SET timestamp='{}',label='{}' WHERE label='{}'",
            entry.entry_type.table(),
            timestamp,
            entry.label,
            orig_entry.label
        );
        conn.execute(&stmt_str, [])?;
    }
    Ok(())
}

pub fn delte_entry(pass: &SecVec<u8>, entry: &Entry) -> Result<()> {
    let conn = connect_db(pass)?;
    let stmt_str = format!(
        "DELETE FROM {} WHERE label='{}'",
        entry.entry_type.table(),
        entry.label
    );
    conn.execute(&stmt_str, [])?;
    Ok(())
}

pub fn rekey(pass: &SecVec<u8>, new_pass: &SecVec<u8>) -> Result<()> {
    let conn = connect_db(pass)?;
    conn.pragma_update(None, "rekey", from_utf8(new_pass.unsecure())?)?;
    Ok(())
}

fn connect_db(pass: &SecVec<u8>) -> Result<Connection> {
    let conn = Connection::open(lib::get_project_file(lib::ProjFiles::Data)?)?;
    conn.pragma_update(None, "key", from_utf8(pass.unsecure())?)?;
    Ok(conn)
}
