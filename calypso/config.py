# -*- coding: utf-8 -*-
#
# This file is part of Calypso Server - Calendar Server
# Copyright © 2008-2011 Guillaume Ayoub
# Copyright © 2008 Nicolas Kandel
# Copyright © 2008 Pascal Halter
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Calypso.  If not, see <http://www.gnu.org/licenses/>.

"""
Calypso configuration module.

Give a configparser-like interface to read and write configuration.

"""

import os
import sys
import configparser

# Default configuration
INITIAL_CONFIG = {
    "server": {
        "host": "",
        "port": "5233",
        "daemon": "False",
        "ssl": "False",
        "certificate": "/etc/apache2/ssl/server.crt",
        "key": "/etc/apache2/ssl/server.key",
        "pidfile": "/var/run/calypso.pid",
#        "user_principal": "/%(user)s",
        "base_prefix": "/",
    },
    "encoding": {
        "request": "utf-8",
        "stock": "utf-8"},
    "acl": {
        "type": "fake",
        "personal": "False",
        "filename": "/etc/calypso/users",
        "encryption": "crypt",
        "pam_service": "passwd",
    },
    "storage": {
        "folder": os.path.expanduser("~/.config/calypso/calendars")
    },
    "headers": {
    },
}

# Create a ConfigParser and configure it
_CONFIG_PARSER = configparser.ConfigParser()

for section, values in INITIAL_CONFIG.items():
    _CONFIG_PARSER.add_section(section)
    for key, value in values.items():
        _CONFIG_PARSER.set(section, key, value)

_CONFIG_PARSER.read("/etc/calypso/config")

xdg_cfg = os.getenv("XDG_CONFIG_HOME")
if xdg_cfg:
    _CONFIG_PARSER.read(os.path.join(xdg_cfg, "calypso/config"))
else:
    _CONFIG_PARSER.read(os.path.expanduser("~/.config/calypso/config"))

cfg = os.getenv("CALYPSO_CONFIG")
if cfg:
    _CONFIG_PARSER.read(cfg)

# Wrap config module into ConfigParser instance
sys.modules[__name__] = _CONFIG_PARSER
