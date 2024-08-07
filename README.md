<div align="center">
  <h1> blackout </h1>
  <h2> Encrypted password/notes and totp manager written in Rust </h2>
</div>

<img src="https://github.com/jandrus/blackout/blob/main/examples/demo.gif?raw=true">

## ✨ Features
- ⌨ CLI based (interactive & args)
- 🔒 Encrypted Password/Note manager
  - 🛡 ️Hide sensitive information
- 🔒 Encrypted TOTP manager
- 🔑 Generate passwords and passphrases 
- 🌱 Generate seed phrases (bip-39 wordlist)
- Customize text editor for managing notes (vim, nano, notepad, etc.)
- Auto-backups available in setup
- Auto-copy generated passwords/passphrases to clipboard (disabled by default)

## 📥 Install
### Cargo (Recommended)
`blackout` can be installed from [crates.io](https://crates.io/crates/blackout).

`cargo install blackout`

### Binary
You can download the pre-built binaries from the [release page](https://github.com/jandrus/blackout/releases).

### Compile source
#### Prerequisites:
- [Rust](https://www.rust-lang.org/)
- [Cargo package manager](https://doc.rust-lang.org/cargo/).

#### Build
```shell
git clone https://github.com/jandrus/blackout.git
cargo build --release
```

This will produce an binary executable file at `target/release/blackout` that you can copy to a directory in your `$PATH`.

## ⚙ Configuration
### Config file
*Note*: If the configuration file does not exist at startup, the user will be prompted to guided through a generation prompt.

#### Location
The configuration file is located in:
| OS      | Config File Location                                                      |
|---------|---------------------------------------------------------------------------|
| Linux   | `$HOME/.config/blackout/config.toml`                                      |
| Windows | `C:\Users\USERNAME\AppData\Roaming\ash\blackout\config\config.toml`       |
| macOS   | `/Users/USERNAME/Library/Application Support/io.ash.blackout\config.toml` |

#### Config Options
- `color`:      This allows for colored output to the terminal. This is recommended. Note: `color` is set to `false`, icons will be disabled.
- `editor`:     This is the command that will be used to render an editor to the user for note input.
- `banner`:     `blackout`, without any arguments, defaults to interactive mode. `banner` enables a banner message on startup.
- `auto_copy`:  Enable/disable generated passwords and passphrases to be automatically copied to the clipboard when generated.
- `icons`:      Enable/disable icons. Note: this requires [nerdfonts](https://www.nerdfonts.com/#home).
- `autobackup`: Enable/disable auto-backups of blackout data when a note/totp url is added or edited.

Here is an example configuration.
```toml
color = true
editor = "vim"
banner = true
auto_copy = false
icons = true
autobackup = true
```

### Wordlist
On startup, the file https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt will be downloaded to the config directory stated above and named `wordlist.txt`. This is a list of 2048 words used for wallet seed phrase generation.

When directed to generate a passphrase, `blackout` will choose the given number of words randomly from this list. Any words added to this file are able to be chosen by the passphrase and seed phrase generator. Entries MUST be on a newline (no comma separated lists, no space separated lists).

## 🛡 ️Security
### Encryption
`blackout` uses [SQLCipher](https://github.com/sqlcipher/sqlcipher) which is a fork of SQLite that adds 256 bit AES encryption of database files and other security features like:
- on-the-fly encryption
- tamper detection
- memory sanitization
- strong key derivation
- algorithms provided by the peer reviewed OpenSSL crypto library

## Usage

<img src="https://github.com/jandrus/blackout/blob/main/examples/usage.gif?raw=true">

### General
```
blackout - Encrypted password/notes and totp manager

Usage: blackout [OPTIONS] [COMMAND]

Commands:
  add, -A       Add note or totp url
  delete, -D    Delete note or totp url
  edit, -E      Edit note or totp url
  export, -X    Export note or totp urls
  fetch, -F     Fetch notes or totp
  generate, -G  Generate password, passphrase, or seed phrase
  list, -L      List note or totp labels only
  help          Print this message or the help of the given subcommand(s)

Options:
  -b, --backup      Backup blackout data (saves a snapshot)
  -c, --changepass  Change master blackout password
  -r, --restore     Restore blackout backup
  -h, --help        Print help
  -V, --version     Print version
```

### Add note or totp url
```
Add note or totp url

Usage: blackout {add|-A} [COMMAND]

Commands:
  note, -N  Add note
  totp, -T  Add TOTP url
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Examples:
- `blackout add` OR `blackout -A`: Interactively add note or totp url.
- `blackout add note` OR `blackout -AN`: Add note via prompt.
- `blackout add totp` OR `blackout -AT`: Add totp url via prompt.

#### Delete note or totp url
```
Delete note or totp url

Usage: blackout {delete|-D} [COMMAND]

Commands:
  note, -N  Delete note
  totp, -T  Delete totp
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Examples:
- `blackout delete` OR `blackout -D`: Interactively delete note or totp url.
- `blackout delete note` OR `blackout -DN`: Interactively delete note.
- `blackout delete totp github` OR `blackout -DT github`: Delete totp url labeled *github*.

#### Edit note or totp url
```
Edit note or totp url

Usage: blackout {edit|-E} [COMMAND]

Commands:
  note, -N  Edit note
  totp, -T  Edit totp url
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Examples:
- `blackout edit` OR `blackout -E`: Interactively edit note or totp url.
- `blackout edit totp` OR `blackout -ET`: Interactively edit totp url.
- `blackout edit note github` OR `blackout -DN github`: Edit note labeled *github*.

### Export data for migration or for parsing
⚠ WARNING: For migrating to a new machine, there is no need to move clear text data
The default behavior is to copy the encrypted database to the current working directory (CWD), data remains encrypted. Use the json or toml flag to export data for use with other programs.
```
Export note or totp urls

Usage: blackout {export|-X} [COMMAND]

Commands:
  both, -B   Export notes and totp url
  notes, -N  Export notes
  totps, -T  Export totp urls
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Examples:
+ `blackout export` OR `blackout -X`: Interactively export data in json, toml, or DB format
+ `blackout export notes` OR `blackout -XN`: Interactively export notes in json, toml, or DB format
+ `blackout export notes -j` OR `blackout -XNj`: Export notes in json format
+ `blackout export totps -t` OR `blackout -XTt`: Export totp urls in toml format
+ `blackout export both -j` OR `blackout -XBj`: Export notes and totp urls in json format

### Fetch note/totp code (Display note or totp code in terminal)
```
Fetch notes or totp

Usage: blackout {fetch|-F} [COMMAND]

Commands:
  note, -N  Fetch note
  totp, -T  Fetch TOTP
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Examples:
+ `blackout fetch` OR `blackout -F`: Interactively fetch note or totp code
+ `blackout fetch note` OR `blackout -FN`: Interactively fetch note
+ `blackout fetch totp github` OR `blackout -FT github`: Fetch totp code labeled *github*

### Generate password, passphrase, or seed phrase
```
Generate password, passphrase, or seed phrase

Usage: blackout {generate|-G} [COMMAND]

Commands:
  pass, -W    Generate password
  phrase, -P  Generate passphrase (BIP-39 word list)
  seed, -S    Generate 24 word seed phrase (BIP-39 word list)
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

#### Generate password
```
Generate password

Usage: blackout generate {pass|-W} [OPTIONS]

Options:
  -l, --length <LENGTH>  length of password. Interactive allows for more options [DEFAULT: 15]
  -i, --interactive      Interactive mode
  -h, --help             Print help
```

Examples:
- `blackout generate pass` OR `blackout -GW`: Generate a password of 15 characters with numbers, upper/lowercase, and special characters.
- `blackout generate pass -i` OR `blackout -GWi`: Interactively generate a password.
- `blackout generate pass -l 18` OR `blackout -GWl 18`: Generate a password of 18 characters.

#### Generate passphrase
```
Generate passphrase (BIP-39 word list)

Usage: blackout generate {phrase|-P} [OPTIONS]

Options:
  -l, --length <NUM_WORDS>  Number of random words to generate [DEFAULT: 5]
  -h, --help                Print help
```

Examples:
- `blackout generate phrase` OR `blackout -GP`: Generate a passphrase of 5 words.
- `blackout generate phrase -l 8` OR `blackout -GPl 8`: Generate a passphrase of 8 words.

#### Generate seed phrase
```
Generate 24 word seed phrase (BIP-39 word list)

Usage: blackout generate {seed|-S}

Options:
  -h, --help  Print help
```

### List notes or totp (LABELS ONLY)
This will only list labels. To get a full list of sensitive content (totp urls and notes) see [[Export data for migration or for parsing]].
```
List note or totp labels only

Usage: blackout {list|-L} [COMMAND]

Commands:
  notes, -N  List note lables
  totps, -T  List TOTP labels
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Examples:
+ `blackout list` OR `blackout -L`: List note and totp labels
+ `blackout list notes` OR `blackout -LN`: List note labels
+ `blackout list totps` OR `blackout -LT`: List totp labels

## Donate
- **BTC**: `bc1qvx8q2xxwesw22yvrftff89e79yh86s56y2p9x9`
- **XMR**: `84t9GUWQVJSGxF8cbMtRBd67YDAHnTsrdWVStcdpiwcAcAnVy21U6RmLdwiQdbfsyu16UqZn6qj1gGheTMkHkYA4HbVN4zS`

## License
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
