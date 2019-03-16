# -*- coding: utf-8 -*-
#
# This file is part of Calypso - CalDAV/CardDAV/WebDAV Server
# Copyright © 2008-2011 Guillaume Ayoub
# Copyright © 2008 Nicolas Kandel
# Copyright © 2008 Pascal Halter
# Copyright © 2011 Keith Packard
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
Calypso collection classes.

Define the main classes of a collection as seen from the server.

"""

import os
import codecs
import time
import hashlib
import logging
import tempfile
import vobject
import re
import subprocess
import vobject.base
import iniparse
import configparser
import threading
from configparser import RawConfigParser as ConfigParser
from . import config, paths

METADATA_FILENAME = ".calypso-collection"

# pylint: enable=F0401

#
# Recursive search for 'name' within 'vobject'
#

def find_vobject_value(vobject, name):

    if vobject.name == name:
        return vobject.value

    for child in vobject.getChildren():
        value = find_vobject_value(child, name)
        if value:
            return value
    return None


class Item(object):

    """Internal item. Wraps a vObject"""

    def __init__(self, text, name=None, path=None, parent_urlpath=None):
        """Initialize object from ``text`` and different ``kwargs``."""

        self.log = logging.getLogger(__name__)

        # Preserve the original text as the contents of the object

        self.text = text

        # Strip out control characters

        text = re.sub(r"[\x01-\x09\x0b-\x1F\x7F]","", text)

        self.object = vobject.readOne(text)

        if 'x-calpyso-name' not in self.object.contents:
            if not name:
                if self.object.name == 'VCARD' or self.object.name == 'VEVENT':
                    if 'uid' not in self.object.contents:
                        self.object.add('UID').value = hashlib.sha1(text.encode('utf-8')).hexdigest()
                    name = self.object.uid.value
                else:
                    for child in self.object.getChildren():
                        if child.name == 'VEVENT' or child.name == 'VCARD':
                            if 'uid' not in child.contents:
                                child.add('UID').value = hashlib.sha1(text.encode('utf-8')).hexdigest()
                            name = child.uid.value
                            break
                    if not name:
                        name = hashlib.sha1(text.encode('utf-8')).hexdigest()
                
            self.object.add("X-CALYPSO-NAME").value = name
        else:
            names = self.object.contents[u'x-calypso-name']
            if len(names) > 1:
                self.object.contents[u'x-calypso-name'] = [names[0]]

        self.path = path
        self.name = self.object.x_calypso_name.value
        if parent_urlpath.endswith("/"):
            self.urlpath = parent_urlpath + self.name
        else:
            self.urlpath = "/".join([parent_urlpath, self.name])
        self.tag = self.object.name
        self.etag = hashlib.sha1(self.text.encode('utf-8')).hexdigest()

    @property
    def is_vcard(self):
        """Whether this item is a vcard entry"""
        if self.object.name == 'VCARD':
            return True
        if self.object.name == 'VEVENT':
            return False
        if self.object.name == 'VTODO':
            return False
        if self.object.name == 'VCALENDAR':
            return False
        for child in self.object.getChildren():
            if child.name == 'VCARD':
                return True
            if child.name == 'VEVENT':
                return False
            if child.name == 'VTODO':
                return False
        return False

    @property
    def is_vcal(self):
        """Whether this item is a vcal entry"""
        if self.object.name == 'VCARD':
            return False
        if self.object.name == 'VEVENT':
            return True
        if self.object.name == 'VTODO':
            return True
        if self.object.name == 'VCALENDAR':
            return True
        for child in self.object.getChildren():
            if child.name == 'VCARD':
                return False
            if child.name == 'VEVENT':
                return True
            if child.name == 'VTODO':
                return True
        return False

    @property
    def is_collection(self):
        return False

    @property
    def file_prefix(self):
        if self.is_vcard:
            return 'card-'
        if self.is_vcal:
            return 'cal-'
        return 'res-'

    @property
    def file_extension(self):
        if self.is_vcard:
            return '.vcf'
        if self.is_vcal:
            return '.ics'
        return '.dav'

    @property
    def length(self):
        return "%d" % len(self.text)

    @property
    def last_modified(self):
        value = find_vobject_value(self.object, "LAST-MODIFIED")
        if value:
            return value.utctimetuple()
        return time.gmtime()

    def match_name(self, name):
        if self.name == name:
            return True
        if self.name + self.file_extension == name:
            return True
        if self.name == name + self.file_extension:
            return True
        return False

    def __str__(self):
        fn = self.object.getChildValue("fn")
        if fn:
            return fn

        if hasattr(self.object, "vevent"):
            summary = self.object.vevent.getChildValue("summary")
            dtstart = self.object.vevent.getChildValue("dtstart")
            if summary and dtstart:
                return "%s (%s)"%(summary, dtstart)
            if summary:
                return summary
            if dtstart:
                return str(dtstart)

            uid = self.object.vevent.getChildValue("uid")
            if uid:
                return uid

        uid = self.object.getChildValue("uid")
        if uid:
            return uid

        return self.name

class Pathtime(object):
    """Path name and timestamps"""

    def __init__(self, path):
        self.path = path
        self.mtime = self.curmtime

    @property
    def curmtime(self):
        return os.path.getmtime(self.path)

    def is_up_to_date(self):
        newmtime = self.curmtime
        if newmtime == self.mtime:
            return True
        self.mtime = newmtime
        return False

class Directory(Pathtime):

    def __init__(self, path, name, parent_urlpath):
        Pathtime.__init__(self, path)
        self.name = name
        self.etag = hashlib.sha1(path.encode('utf-8')).hexdigest()
        if parent_urlpath.endswith("/"):
            self.urlpath = parent_urlpath + self.name
        else:
            self.urlpath = "/".join([parent_urlpath, self.name])

    @property
    def is_vcard(self):
        return False

    @property
    def is_vcal(self):
        return False

    @property
    def is_collection(self):
        return True

    @property
    def file_prefix(self):
        return ''

    @property
    def file_extension(self):
        return ''

    @property
    def text(self):
        return self.path

    @property
    def length(self):
        return "%d" % len(self.path)

    @property
    def last_modified(self):
        return time.gmtime(self.curmtime)
        
    @property
    def is_calendar(self):
        return True

    @property
    def is_addressbook(self):
        return False

class CalypsoError(Exception):
    def __init__(self, name, reason):
        self.name = name
        self.reason = reason

    def __str__(self):
        return "%s: %s" % (self.reason, self.file)

class Collection(object):
    """Internal collection class."""

    def get_description(self):
        try:
            return str(self.metadata.get('collection', 'description'))
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            pass

        try:
            f = codecs.open(os.path.join(self.path, ".git/description"), encoding='utf-8')
            return f.read()
        except:
            # .git/description is not present eg when the complete server is a single git repo
            return self.urlpath

    def read_file(self, path):
        text = codecs.open(path,encoding='utf-8').read()
        item = Item(text, None, path, self.urlpath)
        return item

    def insert_file(self, path, name):
        if os.path.isdir(path):
            try:
                item = Directory(path, name, self.urlpath)
                self.my_dirs.append(item)
            except Exception as ex:
                self.log.exception("Insert %s failed", path)
                return
        else:
            try:
                item = self.read_file(path)
                self.my_items.append(item)
            except Exception as ex:
                self.log.exception("Insert %s failed", path)
                return

    def remove_file(self, path):
        old_items=[]
        for old_item in self.my_items:
            if old_item.path == path:
                old_items.append(old_item)
        for old_item in old_items:
            self.my_items.remove(old_item)
        old_dirs=[]
        for old_dir in self.my_dirs:
            if old_dir.path == path:
                old_dirs.append(old_dir)
        for old_dir in old_dirs:
            self.my_dirs.remove(old_dir)
        
    def scan_file(self, path, name):
        self.remove_file(path)
        self.insert_file(path, name)

    __metadatafile = property(lambda self: os.path.join(self.path, METADATA_FILENAME))

    def scan_metadata(self, force):
        try:
            mtime = os.path.getmtime(self.__metadatafile)
        except OSError:
            mtime = 0
            force = True

        if not force and mtime == self.mtime and self.metadata is not None:
            return

        parser = ConfigParser()
        parser.read(self.__metadatafile)
        self.metadata = parser

    def scan_dir(self, force):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            mtime = 0
            force = True

        self.scan_metadata(force)

        if not force and mtime == self.mtime:
            return
        self.log.debug("Scan %s", self.path)
        self.mtime = mtime
        filenames = os.listdir(self.path)
        newfiles = []
        for filename in filenames:
            if filename == METADATA_FILENAME:
                continue
            if filename == '.git':
                continue
            filepath = os.path.join(self.path, filename)
            for file in self.files:
                if filepath == file.path:
                    newfiles.append(file)
                    if not file.is_up_to_date():
                        self.log.debug("Changed %s", filepath)
                        self.scan_file(filepath, filename)
                    break
            else:
                self.log.debug("New %s", filepath)
                newfiles.append(Pathtime(filepath))
                self.insert_file(filepath, filename)

        for file in self.files:
            if os.path.basename(file.path) not in filenames:
                self.log.debug("Removed %s", file.path)
                self.remove_file(file.path)

        h = hashlib.sha1()
        self._text = ''
        for item in self.my_items:
            if getattr(item, 'etag', None):
                h.update(item.etag.encode('utf-8'))
            else:
                h.update(item.ctag.encode('utf-8'))
            self._text = self._text + item.text
        self._ctag = '%d-' % self.mtime + h.hexdigest()
        self.files = newfiles

    def __init__(self, path):
        """Initialize the collection with ``cal`` and ``user`` parameters."""

        self.log = logging.getLogger(__name__)
        self.encoding = "utf-8"
        self.urlpath = path
        self.owner = paths.url_to_owner(path)
        self.path = paths.url_to_file(path)
        self.files = []
        self.my_items = []
        self.my_dirs = []
        self.mtime = 0
        self._text = ''
        self._ctag = ''
        self.etag = hashlib.sha1(self.path.encode('utf-8')).hexdigest()
        self.metadata = None
        self.metadata_mtime = None
        self.scan_dir(False)
        self.tag = "Collection"
        self.lock = threading.Lock()

    def __str__(self):
        return "Calendar-%s (at %s)" % (self.name, self.path)

    def __repr__(self):
        return "<Calendar %s>" % (self.name)
        
    def acquire(self):
        self.lock.acquire()

    def release(self):
        self.lock.release()

    def __enter__(self):
        self.lock.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.__exit__(exc_type, exc_val, exc_tb)

    def has_git(self):
        return True

    def git_commit(self, context):
        args = ["git", "commit", "--allow-empty"]
        env = {}

        message = context.get('action', 'other action')

        if "user" in context:
            # use environment variables instead of --author to avoid git
            # looking it up in previous commits if it doesn't seem well-formed
            env['GIT_AUTHOR_NAME'] = context['user'] or "unknown"
            env['GIT_AUTHOR_EMAIL'] = "%s@webdav"%context['user']
            # supress a chatty message that we could configure author
            # information explicitly in the config file. (slicing it in after
            # the git command as position is important with git arguments)
            args[1:1] = ["-c", "advice.implicitIdentity=false"]
        if "user-agent" in context:
            message += u"\n\nUser-Agent: %r"%context['user-agent']

        args.extend(["-m", message.encode('utf8')])

        subprocess.check_call(args, cwd=self.path, env=env)

    def git_add(self, path, context):
        if self.has_git():
            subprocess.check_call(["git", "add", os.path.basename(path)], cwd=self.path)
            self.git_commit(context=context)
    
    def git_rm(self, path, context):
        if self.has_git():
            subprocess.check_call(["git", "rm", os.path.basename(path)], cwd=self.path)
            self.git_commit(context=context)

    def git_change(self, path, context):
        if self.has_git():
            subprocess.check_call(["git", "add", os.path.basename(path)], cwd=self.path)
            self.git_commit(context=context)
            # Touch directory so that another running instance will update
            try:
                os.utime(self.path, None)
            except Exception as ex:
                self.log.exception("Failed to set directory mtime")
            
    def write_file(self, item):
        fd, path = tempfile.mkstemp(item.file_extension, item.file_prefix, dir=self.path)
        self.log.debug('Trying to write to %s', path)
        file = os.fdopen(fd, 'w')
        file.write(item.text)
        file.close()
        self.log.debug('Wrote %s to %s', file, path)
        return path

    def create_file(self, item, context):
        # Create directory if necessary
        self.log.debug("Add %s", item.name)
        if not os.path.exists(os.path.dirname(self.path)):
            try:
                os.makedirs(os.path.dirname(self.path))
            except OSError as ose:
                self.log.exception("Failed to make collection directory %s: %s", self.path, ose)
                raise

        context['action'] = u'Add %s'%item

        try:
            path = self.write_file(item)
            self.git_add(path, context=context)
            self.scan_dir(True)
        except OSError as ex:
            self.log.exception("Error writing file")
            raise
        except Exception as ex:
            self.log.exception("Caught Exception")
            self.log.debug("Failed to create %s: %s", self.path,  ex)
            raise

    def destroy_file(self, item, context):
        self.log.debug("Remove %s", item.name)

        context['action'] = u'Remove %s'%item

        try:
            os.unlink(item.path)
            self.git_rm(item.path, context=context)
            self.scan_dir(True)
        except Exception as ex:
            self.log.exception("Failed to remove %s", item.path)
            raise

    def rewrite_file(self, item, context):
        self.log.debug("Change %s", item.name)

        context['action'] = u'Modify %s'%item

        try:
            new_path = self.write_file(item)
            os.rename(new_path, item.path)
            self.scan_file(item.path, item.name)
            self.git_change(item.path, context=context)
            self.scan_dir(True)
        except Exception as ex:
            self.log.exception("Failed to rewrite %s", item.path)
            raise
        
    def get_item(self, name):
        """Get collection item called ``name``."""
        for item in self.my_items:
            if item.match_name(name):
                return item
        return None

    def get_items(self, name):
        """Get collection items called ``name``."""
        items=[]
        for item in self.my_items:
            if item.match_name(name):
                items.append(item)
        return items

    def append(self, name, text, context):
        """Append items from ``text`` to collection.

        If ``name`` is given, give this name to new items in ``text``.

        """

        self.log.debug('append name %s', name)
        try:
            new_item = Item(text, name, None, self.urlpath)
        except Exception as e:
            self.log.exception("Cannot create new item")
            raise
        old_item = self.get_item(new_item.name)
        if old_item:
            self.log.debug("Item %s already present %s" , new_item.name, old_item.path)
            raise CalypsoError(new_item.name, "Item already present")
        self.log.debug("New item %s", new_item.name)
        self.create_file(new_item, context=context)
        return new_item

    def remove(self, name, context):
        """Remove object named ``name`` from collection."""
        self.log.debug("Remove object %s", name)
        for old_item in self.my_items:
            if old_item.match_name(name):
                self.destroy_file(old_item, context=context)
                
    def replace(self, name, text, context):
        """Replace content by ``text`` in objet named ``name`` in collection."""

        path=None
        old_item = self.get_item(name)
        if old_item:
            path = old_item.path

        try:
            new_item = Item(text, name, path, self.urlpath)
        except Exception:
            self.log.exception("Failed to replace %s", name)
            raise

        ret = False
        if path is not None:
            self.log.debug('rewrite path %s', path)
            self.rewrite_file(new_item, context=context)
        else:
            self.log.debug('remove and append item %s', name)
            self.remove(name)
            self.append(name, text, context=context)
        return new_item

    def import_item(self, new_item, path):
        old_item = self.get_item(new_item.name)
        if old_item:
            new_item.path = old_item.path
            self.rewrite_file(new_item, context={})
            self.log.debug("Updated %s from %s", new_item.name, path)
        else:
            self.create_file(new_item, context={})
            self.log.debug("Added %s from %s", new_item.name, path)

    def import_file(self, path):
        """Merge items from ``path`` to collection.
        """

        try:
            new_object = vobject.readComponents(codecs.open(path,encoding='utf-8').read())
            for new_ics in new_object:
                if new_ics.name == 'VCALENDAR':

                    events = new_ics.vevent_list
                    for ve in events:
                        # Check for events with both dtstart and duration entries and
                        # delete the duration one
                        if 'dtstart' in ve.contents and 'duration' in ve.contents:
                            del ve.contents['duration']
                        new_ics.vevent_list = [ve]
                        new_item = Item(new_ics.serialize().decode('utf-8'), None, path, self.urlpath)
                        self.import_item(new_item, path)
                else:
                    new_item = Item(new_ics.serialize().decode('utf-8'), None, path, self.urlpath)
                    self.import_item(new_item, path)
            return True
        except Exception as ex:
            self.log.exception("Failed to import: %s", path)
            return False

    def write(self, headers=None, items=None):
        return True

    @property
    def is_collection(self):
        return True

    @property
    def ctag(self):
        self.scan_dir(False)
        """Ctag from collection."""
        return self._ctag

    @property
    def name(self):
        """Collection name."""
        return self.path.split(os.path.sep)[-1]

    @property
    def text(self):
        """Collection as plain text."""
        self.scan_dir(False)
        return self._text

    @property
    def color(self):
        """Color."""
        try:
            return "#%s" % self.metadata.get('collection', 'color')
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return None

    @property
    def headers(self):
        """Find headers items in collection."""
        return []

    @property
    def items(self):
        """Get list of all items in collection."""
        self.scan_dir(False)
        return self.my_items

    @property
    def dirs(self):
        """Get list of all dirs in collection."""
        self.scan_dir(False)
        return self.my_dirs

    @property
    def last_modified(self):
        """Get the last time the collection has been modified.

        The date is formatted according to rfc1123-5.2.14.

        """
        self.scan_dir(False)
        return time.gmtime(self.mtime)

    @property
    def length(self):
        return "%d" % len(self.text)

    @property
    def is_addressbook(self):
        try:
            return self.metadata.getboolean('collection', 'is-addressbook')
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return True

    @property
    def is_calendar(self):
        try:
            return self.metadata.getboolean('collection', 'is-calendar')
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return True
