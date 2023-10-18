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

""" Password Managment script using GPG and python """

import os
import sys
import time
import configparser
from subprocess import call
from getpass import getpass
import gnupg
from termcolor import colored


BLACKOUT_DIR            = f"{os.environ['HOME']}/.local/share/blackout/"
CONF_DIR                = f"{os.environ['HOME']}/.config/blackout/"
BLACKOUT_FILE           = f"{BLACKOUT_DIR}blackout.gpg"
OPENED_BLACKOUT_FILE    = f"{BLACKOUT_DIR}blackout.ini"
CONF_FILE               = f"{CONF_DIR}config.ini"
ALLOWED_ATTEMPTS        = 3
BANNER = """
__________.__                 __                 __
\______   \  | _____    ____ |  | ______  __ ___/  |_
 |    |  _/  | \__  \ _/ ___\|  |/ /  _ \|  |  \   __|
 |    |   \  |__/ __ \|  \___|    <  <_> )  |  /|  |
 |______  /____(____  /\___  >__|_ \____/|____/ |__|
        \/          \/     \/     \/
"""

conf = configparser.ConfigParser()
conf.read(CONF_FILE)
if not conf.sections():
    print(f"Configuration ({CONF_FILE}) was not found. Please restore from backup or run setup.")
    sys.exit(1)
EDITOR          = conf.get("CONF", "editor")
BACKUP_FILE     = conf.get("CONF", "backup-file")
EDITOR_HISTORY  = conf.get("CONF", "editor-history")


def decrypt_contents(password):
    """ Returns status OK(boolean) of decryption attempt with given password """
    try:
        with open(BLACKOUT_FILE, 'rb') as file_:
            return gnupg.GPG().decrypt_file(file_, passphrase=password, output=OPENED_BLACKOUT_FILE)
    except FileNotFoundError:
        pprint(f"Error: {BLACKOUT_FILE} not found")
        raise

def encrypt_contents(password):
    """ Returns status obj of encryption attempt with given password """
    try:
        with open(OPENED_BLACKOUT_FILE, 'rb') as file_:
            return gnupg.GPG().encrypt_file(file_,
                    recipients=None,
                    symmetric='AES256',
                    passphrase=password,
                    output=BLACKOUT_FILE)
    except FileNotFoundError:
        pprint(f"Error: {OPENED_BLACKOUT_FILE} not found")
        raise

def change_password(orig_password, attempts):
    """ Change password for blackout file """
    clear_screen()
    if attempts >= ALLOWED_ATTEMPTS:
        raise ValueError('Allowed password attempts exceeded')
    ans = input(colored('Would you like to change your blackout password? (y/n): ', 'red')).upper()[0]
    if ans == 'Y':
        while True:
            password_0 = getpass(colored('Enter original password: ', 'green'))
            password_1 = getpass(colored('Enter new password: ', 'green'))
            password_2 = getpass(colored('Re-enter new password: ', 'green'))
            if password_1 == password_2 and password_0 == orig_password:
                status = encrypt_contents(password_1)
                if status.ok:
                    pprint(status.status.upper(), 'yellow')
                    break
                pprint(status.status.upper(), 'red')
                pprint(status.status.stderr.upper(), 'red')
                break
            pprint('Passwords DO NOT match or ORIGINAL password is wrong. Try Again', 'red')
            time.sleep(4)
            attempts += 1
            change_password(orig_password, attempts)

def parse_sections(conf):
    """ Parse section tags from sections """
    sectioned_tags = {}
    sections = conf.sections()
    for section in sections:
        try:
            tag = conf[section]['tag']
        except KeyError:
            tag = 'None'
        if tag in sectioned_tags.keys():
            sectioned_tags[tag].append(section)
        else:
            sectioned_tags[tag] = [section]
    return sectioned_tags

def get_content(conf_file):
    """ Get content from opened Blackout File """
    conf = configparser.ConfigParser()
    conf.read(conf_file)
    if not conf.sections():
        raise FileNotFoundError(f"{conf_file} was not found. Please restore from backup or run setup.")
    return conf

def get_attribute(attributes, allow_back=True, allow_all=False):
    """ Get attributes from user """
    counter = 1
    clear_screen()
    for attr in attributes:
        pprint(f'{counter}:\t{attr}')
        counter += 1
    if allow_all:
        pprint('A:\tAll')
    if allow_back:
        pprint('B:\tBack')
    choice = input(colored('Enter Choice: ', 'green'))
    if allow_back and choice.upper()[0] == 'B':
        return 0
    if allow_all and choice.upper()[0] == 'A':
        return 1
    choice = int(choice)
    if choice > len(attributes) or choice < 1:
        pprint('Invalid Selection', 'red')
        time.sleep(4)
        return get_attribute(attributes)
    return attributes[choice-1]

def retrieve_data():
    """ Retrieve information for sections within opened blackout file """
    conf = get_content(OPENED_BLACKOUT_FILE)
    sectioned_tags = parse_sections(conf)
    tags = list(sectioned_tags.keys())
    tag = get_attribute(tags, allow_back=False)
    sections = sectioned_tags[tag]
    section = get_attribute(sections)
    if section == 0:
        retrieve_data()
        return
    options = conf.options(section)
    options.remove('tag')
    option = get_attribute(options, allow_all=True)
    if option == 0:
        retrieve_data()
        return
    if option == 1:
        clear_screen()
        for option in options:
            if option == 'tag':
                continue
            attribute = conf.get(section, option)
            pprint('{:<8}\t{}'.format(option, attribute), 'cyan')
        print()
    else:
        clear_screen()
        attribute = conf.get(section, option)
        pprint('{:<8}\t{}'.format(option, attribute), 'cyan')
        print()

def edit_file(password):
    """ Edit opened blackout file with EDITOR and CLEAR history file """
    try:
        call([EDITOR, OPENED_BLACKOUT_FILE])
    except FileNotFoundError as exc:
        raise FileNotFoundError("Selected editor or Blackout file is not configured properly.") from exc
    # os.system(f'shred -u {EDITOR_HISTORY}')
    status = encrypt_contents(password)
    if status.ok:
        pprint('CHANGES SAVED', 'yellow')
    else:
        raise ValueError(f"Encryption failed ({status.status.stderr.upper()}). Please restore backup or run setup.")
    status = decrypt_contents(password)
    if status.ok:
        pprint(status.status.upper(), 'yellow')
    else:
        raise ValueError(f"Decryption failed ({status.status.stderr.upper()}). Please restore backup or run setup.")

def get_action():
    """ Return action to complete """
    while True:
        pprint('E: to edit information\nR: to retrieve data\nP: to change password\nX: to exit')
        choice = input(colored('Enter Choice: ', 'green')).upper()[0]
        if choice in ('E', 'R', 'P', 'X'):
            return choice
        pprint('Invalid Option', 'red')

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
    print_banner()

def delete_unencrypted_file():
    """ Remove clear text file if it exists """
    if os.path.isfile(OPENED_BLACKOUT_FILE):
        os.system(f'shred -u {OPENED_BLACKOUT_FILE}')
        os.system(f'cp -u {BLACKOUT_FILE} {BACKUP_FILE}')
    pprint('BLACKOUT CLOSED', 'yellow')

def main():
    try:
        clear_screen()
        attempts = 0
        while attempts < ALLOWED_ATTEMPTS:
            attempts += 1
            password = getpass(colored('Enter Password: ', 'red'))
            status = decrypt_contents(password)
            if status.ok:
                pprint(status.status.upper(), 'yellow')
                break
            pprint('Incorrect password', 'red')
        if attempts >= ALLOWED_ATTEMPTS:
            raise ValueError('Allowed password attempts exceeded')
        while True:
            choice = get_action()
            if choice == 'E':
                edit_file(password)
            elif choice == 'R':
                retrieve_data()
            elif choice == 'P':
                change_password(password, 0)
            else:
                break
    except Exception as e:
        raise e


try:
    if __name__ == '__main__':
        main()
except KeyboardInterrupt:
    pprint('\nKeyboardInterrupt: Goodbye')
except Exception as e:
    pprint(f'\n{type(e).__name__} {str(e)}', 'red')
finally:
    delete_unencrypted_file()
