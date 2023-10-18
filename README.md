# Blackout - simple password manager

## Description  

Blackout is a simple password managment script written in Python that uses GnuPG bindings to secure your passwords or any information you deem sensitive locally on your machine.


## Requirements  

Install these packages prior to initializing and running Blackout.

* `python-gnupg` - This module allows easy access to GnuPG’s key management, encryption and signature functionality from Python programs.
* `python-termcolor` - ANSI color formatting for output in terminal.
* `shred` - overwrite a file to hide its contents, and optionally delete it. ***Note:** This should already be installed and should not require any action.* 
* `vim` - Vi IMproved, a programmer's text editor (*Optional: `vim` is the default editor. If this is not desired, please configure in `~/.config/blackout/conf.ini`.*)

### Arch

`$ sudo pacman -S python-gnupg python-termcolor vim`

### Debian/Ubuntu/Linux Mint

`$ sudo apt install python3-gnupg python3-termcolor vim`


##  Use  

1. Clone repository: `git clone https://github.com/jandrus/blackout` 
1. Install requirements
1. Run setup: `python3 setup.py`
1. Execute Blackout: `python3 blackout.py`


## Donate  

* XMR: 84t9GUWQVJSGxF8cbMtRBd67YDAHnTsrdWVStcdpiwcAcAnVy21U6RmLdwiQdbfsyu16UqZn6qj1gGheTMkHkYA4HbVN4zS

* BTC: bc1q7y20wr2n5qt2fxe569llvz5a0qsnpsz4decplr


## TODO  

* Windows client


## License

Blackout - Simple password manager Copyright (C) 2023 James Andrus Email: jandrus@citadel.edu

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.
