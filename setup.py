#!/usr/bin/env python3
#
#
# Blackout - Simple password manager
# Copyright (C) 2023 James Andrus
# Email: jandrus@citadel.edu

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" Setup script for Blackout """

import os
import time
from getpass import getpass
from pathlib import Path


BANNER = """
__________.__                 __                 __
\______   \  | _____    ____ |  | ______  __ ___/  |_
 |    |  _/  | \__  \ _/ ___\|  |/ /  _ \|  |  \   __|
 |    |   \  |__/ __ \|  \___|    <  <_> )  |  /|  |
 |______  /____(____  /\___  >__|_ \____/|____/ |__|
        \/          \/     \/     \/
"""
BLACKOUT_DIR            = f"{os.environ['HOME']}/.local/share/blackout/"
CONF_DIR                = f"{os.environ['HOME']}/.config/blackout/"
BLACKOUT_FILE           = f"{BLACKOUT_DIR}blackout.gpg"
OPENED_BLACKOUT_FILE    = f"{BLACKOUT_DIR}blackout.ini"
BACKUP_FILE             = f"{BLACKOUT_DIR}blackout.backup"
CONF_FILE               = f"{CONF_DIR}config.ini"



try:
    import gnupg
except ImportError as exc:
    print(f"Error: {exc}")
    print("Please install python-gnupg (python3-gnupg).")

try:
    from termcolor import colored
except ImportError as exc:
    print(f"Error: {exc}")
    print("Please install python-termcolor (python3-termcolor).")


def encrypt_contents(password):
    """ Returns status obj of encryption attempt with given password """
    with open(OPENED_BLACKOUT_FILE, 'rb') as file_:
        return gnupg.GPG().encrypt_file(file_,
                recipients=None,
                symmetric='AES256',
                passphrase=password,
                output=BLACKOUT_FILE)

def get_password():
    """ Get user provided password """
    clear_screen()
    print_banner()
    pprint("Please enter your new Blackout password.\nThis password will be required everytime to access the information you place into your Blackout file.\nKEEP THIS PASSWORD SAFE AND SECURE. THERE IS NO PASSWORD RECOVERY.\n")
    password_1 = getpass(colored('Enter password: ', 'green'))
    password_2 = getpass(colored('Re-enter password: ', 'green'))
    if password_1 == password_2:
        status = encrypt_contents(password_1)
        if status.ok:
            os.system(f'shred -u {OPENED_BLACKOUT_FILE}')
            return
    pprint('Passwords DO NOT match. Try Again', 'red')
    time.sleep(4)
    get_password()

def create_dirs():
    """ Create directories for Blackout """
    Path(CONF_DIR).mkdir(parents=True, exist_ok=True)
    Path(BLACKOUT_DIR).mkdir(parents=True, exist_ok=True)

def create_files():
    """ Create files and add default content """
    with open(CONF_FILE, 'w', encoding='utf-8') as file_:
        file_.write(f"[CONF]\neditor = vim\nbackup-file = {BACKUP_FILE}\neditor-history = ~/.viminfo\n# editor-history is an optional arg. If set, Blackout will shred history file on close. If not desired, change to None.")
    pprint(f"Configuration file has been created ({CONF_FILE}).")
    with open(OPENED_BLACKOUT_FILE, 'w', encoding='utf-8') as file_:
        file_.write("[EXAMPLE]\nTAG = example\nEMAIL = nick.van@saberhagen.com\nPASSWORD = SuperSecurePasswordExample\nUSERNAME = username-example")
    pprint("Initial Blackout file created.")

def pprint(string_, color='green'):
    """ Print string in color:
    Valid colors -> grey, red, green, yellow, blue, magenta, cyan, white """
    print(colored(string_, color))

def print_banner(color='red'):
    """ Print large strings in color and centered in terminal:
    Valid colors -> grey, red, green, yellow, blue, magenta, cyan, white """
    cols = os.get_terminal_size().columns
    lines = BANNER.split('\n')
    max_len = 0
    for line in lines:
        if len(line) > max_len:
            max_len = len(line)
    for line in lines:
        pprint(' '*((cols - max_len)//2) + line, color)
    pprint('-'*cols, color)

def clear_screen():
    """ Clear terminal/command prompt of text """
    os.system('cls' if os.name == 'nt' else 'clear')



clear_screen()
print_banner()
pprint(f"Welcome {os.getlogin()}!")
create_dirs()
create_files()
time.sleep(3)
get_password()
pprint("Setup complete!")
