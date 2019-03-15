#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# This file is part of Calypso Server - Calendar Server
# Copyright © 2009-2011 Guillaume Ayoub
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
Calypso CalDAV server
======================

The Calypso Project is a CalDAV calendar server.  It aims to be a light
solution, easy to use, easy to install, easy to configure.  As a consequence,
it requires few software dependances and is pre-configured to work
out-of-the-box.

The Calypso Project runs on most of the UNIX-like platforms (Linux, BSD,
MacOS X) and Windows.  It is known to work with Evolution 2.30+, Lightning 0.9+
and Sunbird 0.9+. It is free and open-source software, released under GPL
version 3.

For further information, please visit the `Calypso Website
<http://keithp.com/blogs/calypso/>`_.

"""

import os
from distutils.command.build_scripts import build_scripts
from setuptools import setup

try:
    from calypso import VERSION
except ImportError as e:
    print('Error importing Calypso, probably dependencies are not installed')
    print(e)
    VERSION = '0.0.1'
    print('Assuming version %s' % VERSION)

# build_scripts is known to have a lot of public methods
# pylint: disable=R0904
class BuildScripts(build_scripts):
    """Build the package."""
    def run(self):
        """Run building."""
        # These lines remove the .py extension from the calypso executable
        self.mkpath(self.build_dir)
        for script in self.scripts:
            root, _ = os.path.splitext(script)
            self.copy_file(script, os.path.join(self.build_dir, root))
# pylint: enable=R0904


# When the version is updated, ``calypso.VERSION`` must be modified.
# A new section in the ``NEWS`` file must be added too.
setup(
    name="calypso",
    version=VERSION,
    description="CalDAV and CardDAV Server",
    long_description=__doc__,
    author="Keith Packard",
    author_email="keithp@keithp.com",
    url="http://keithp.com/blogs/calypso/",
    download_url="https://anonscm.debian.org/cgit/calypso/calypso.git/",
    license="GNU GPL v3",
    platforms="Any",
    packages=["calypso", "calypso.acl"],
    provides=["calypso"],
    install_requires=["daemon","vobject"],
    tests_require=['nose>=0.11.1'],
    scripts=["calypso.py"],
    cmdclass={"build_scripts": BuildScripts},
    keywords=["calendar", "CalDAV"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Topic :: Office/Business :: Groupware"])
