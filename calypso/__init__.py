# -*- coding: utf-8 -*-
#
# This file is part of Calypso - CalDAV/CardDAV/WebDAV Server
# Copyright © 2011 Keith Packard
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
Calypso Server module.

This module offers 3 useful classes:

- ``HTTPServer`` is a simple HTTP server;
- ``HTTPSServer`` is a HTTPS server, wrapping the HTTP server in a socket
  managing SSL connections;
- ``CollectionHTTPHandler`` is a WebDAV request handler for HTTP(S) servers.

To use this module, you should take a look at the file ``calypso.py`` that
should have been included in this package.

"""

import os
import os.path
import base64
import socket
import time
import email.utils
import logging
import email
import ssl
import threading
from http import client, server


from . import acl, config, webdav, xmlutils, paths, gssapi

log = logging.getLogger()
ch = logging.StreamHandler()
formatter = logging.Formatter("%(message)s")
ch.setFormatter (formatter)
log.addHandler(ch)
negotiate = gssapi.Negotiate(log)

http_server = server.HTTPServer
try:
    from http.server import ThreadingHTTPServer
    http_server = server.ThreadingHTTPServer
except ImportError:
    pass

VERSION = "2.0"

def _check(request, function):
    """Check if user has sufficient rights for performing ``request``."""
    # ``_check`` decorator can access ``request`` protected functions
    # pylint: disable=W0212
    owner = user = password = None
    negotiate_success = False

    if request._collection:
        owner = request._collection.owner

    authorization = request.headers.get("Authorization", None)
    if authorization:
        if authorization.startswith("Basic"):
            challenge = authorization.lstrip("Basic").strip().encode("ascii")
            plain = request._decode(base64.b64decode(challenge))
            user, password = plain.split(":")
        elif negotiate.enabled():
            user, negotiate_success = negotiate.try_aaa(authorization, request, owner)

    # Also send UNAUTHORIZED if there's no collection. Otherwise one
    # could probe the server for (non-)existing collections.
    if request.server.acl.has_right(owner, user, password) or negotiate_success:
        function(request, context={"user": user, "user-agent": request.headers.get("User-Agent", None)})
    else:
        request.send_calypso_response(client.UNAUTHORIZED, 0)
        if negotiate.enabled():
            request.send_header("WWW-Authenticate", "Negotiate")
        else:
            request.send_header(
                "WWW-Authenticate",
                'Basic realm="Calypso CalDAV/CardDAV server - password required"')
        request.end_headers()
    # pylint: enable=W0212


class HTTPServer(server.HTTPServer):
    """HTTP server."""
    PROTOCOL = "http"

    # Maybe a Pylint bug, ``__init__`` calls ``server.HTTPServer.__init__``
    # pylint: disable=W0231
    def __init__(self, address, handler):
        """Create server."""
        http_server.__init__(self, address, handler)
        self.acl = acl.load()
    # pylint: enable=W0231


class HTTPSServer(HTTPServer):
    """HTTPS server."""
    PROTOCOL = "https"

    def server_bind(self):
        HTTPServer.server_bind(self)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(os.path.expanduser(config.get("server", "certificate")),
                                keyfile=os.path.expanduser(config.get("server", "key")))

        self.socket = context.wrap_socket(self.socket,server_side=True)

class CollectionHTTPHandler(server.BaseHTTPRequestHandler):
    """HTTP requests handler for WebDAV collections."""
    _encoding = config.get("encoding", "request")

    # Decorator checking rights before performing request
    check_rights = lambda function: lambda request: _check(request, function)

    # We do set Content-Length on all replies, so we can use HTTP/1.1
    # with multiple requests (as desired by the android CalDAV sync program

    protocol_version = 'HTTP/1.1'

    timeout = 90

    server_version = "Calypso/%s" % VERSION
    queued_headers = {}

    def queue_header(self, keyword, value):
        self.queued_headers[keyword] = value

    def end_headers(self):
        """
        Send out all queued headers and invoke or super classes
        end_header.
        """
        if self.queued_headers:
            for keyword, val in self.queued_headers.items():
                self.send_header(keyword, val)
            self.queued_headers = {}
        return server.BaseHTTPRequestHandler.end_headers(self)

    def address_string(self):
        return str(self.client_address[0])

    def send_connection_header(self):
        conntype = "Close"
        if self.close_connection == 0:
            conntype = "Keep-Alive"
        self.send_header("Connection", conntype)

    def send_calypso_response(self, response, length):
        self.send_response(response)
        self.send_connection_header()
        self.send_header("Content-Length", length)
        for header, value in config.items('headers'):
            self.send_header(header, value)


    def handle_one_request(self):
        """Handle a single HTTP request.

        You normally don't need to override this method; see the class
        __doc__ string for information on how to handle specific HTTP
        commands such as GET and POST.

        """
        try:
            self.wfile.flush()
            self.close_connection = 1

            self.connection.settimeout(5)

            self.raw_requestline = self.rfile.readline(65537)

            self.connection.settimeout(90)

            if len(self.raw_requestline) > 65536:
                log.error("Read request too long")
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                log.error("Connection closed")
                return
            log.debug("First line '%s'", self.raw_requestline)
            if not self.parse_request():
                # An error code has been sent, just exit
                self.close_connection = 1
                return
            # parse_request clears close_connection on all http/1.1 links
            # it should only do this if a keep-alive header is seen
            self.close_connection = 1
            conntype = self.headers.get('Connection', "")
            if (conntype.lower() == 'keep-alive'
                and self.protocol_version >= "HTTP/1.1"):
                log.debug("keep-alive")
                self.close_connection = 0
            reqlen = self.headers.get('Content-Length',"0")
            log.debug("reqlen %s", reqlen)
            self.xml_request = self.rfile.read(int(reqlen))
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                log.error("Unsupported method (%r)", self.command)
                self.send_error(501, "Unsupported method (%r)" % self.command)
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush() #actually send the response if not already done.
        except socket.timeout as e:
            #a read or a write timed out.  Discard this connection
            log.error("Request timed out: %r", e)
            self.close_connection = 1
            return
        except ssl.SSLError as x:
            #an io error. Discard this connection
            log.error("SSL request error: %r", x.args[0])
            self.close_connection = 1
            return


    collections = {}
    collections_lock = threading.Lock()

    @property
    def _collection(self):
        """The ``webdav.Collection`` object corresponding to the given path."""
        path = paths.collection_from_path(self.path)
        if not path:
            return None
        with CollectionHTTPHandler.collections_lock:
            if not path in CollectionHTTPHandler.collections:
                CollectionHTTPHandler.collections[path] = webdav.Collection(path)
            return CollectionHTTPHandler.collections[path]

    def _decode(self, text):
        """Try to decode text according to various parameters."""
        # List of charsets to try
        charsets = []

        # First append content charset given in the request
        content_type = self.headers.get("Content-Type", None)
        if content_type and "charset=" in content_type:
            charsets.append(content_type.split("charset=")[1].strip())
        # Then append default Calypso charset
        charsets.append(self._encoding)
        # Then append various fallbacks
        charsets.append("utf-8")
        charsets.append("iso8859-1")

        # Try to decode
        for charset in charsets:
            try:
                return text.decode(charset)
            except UnicodeDecodeError:
                pass
        raise UnicodeDecodeError

    # Naming methods ``do_*`` is OK here
    # pylint: disable=C0103

    @check_rights
    def do_GET(self, context):
        """Manage GET request."""
        self.do_get_head(context, True)

    @check_rights
    def do_HEAD(self, context):
        """Manage HEAD request."""
        self.do_get_head(context, False)

    def do_get_head(self, context, is_get):
        """Manage either GET or HEAD request."""

        self._answer = ''
        answer_text = ''
        code = client.OK
        last_modified = ''
        try:
            item_name = paths.resource_from_path(self.path)
            if self._collection:
                with self._collection:
                    if item_name:
                        # Get collection item
                        item = self._collection.get_item(item_name)
                        if item:
                            if is_get:
                                answer_text = item.text
                            etag = item.etag
                        else:
                            code = client.GONE
                    else:
                        # Get whole collection
                        if is_get:
                            answer_text = self._collection.text
                        etag = self._collection.etag
                    last_modified = self._collection.last_modified

                if len(answer_text):
                    try:
                        self._answer = answer_text.encode(self._encoding,"xmlcharrefreplace")
                    except UnicodeDecodeError:
                        answer_text = answer_text.decode(errors="ignore")
                        self._answer = answer_text.encode(self._encoding,"ignore")
            else:
                code = client.NOT_FOUND

        except Exception:
            log.exception("Failed HEAD for %s", self.path)
            code = client.BAD_REQUEST

        self.send_calypso_response(code, len(self._answer))
        if code == client.OK:
            self.send_header("Content-Type", "text/calendar")
            self.send_header("Last-Modified", email.utils.formatdate(time.mktime(last_modified)))
            self.send_header("ETag", etag)
        self.end_headers()
        if len(self._answer):
            self.wfile.write(self._answer)

    def if_match(self, items):
        for item in items:
            header = self.headers.get("If-Match", item.etag)
            header = email.utils.unquote(header)
            log.debug("header '%s' etag '%s'" % (header, item.etag))
            if header == item.etag:
                return True
            quoted = '"' + item.etag + '"'
            if header == quoted:
                return True
            extraquoted = email.utils.quote(quoted)
            if header == extraquoted:
                return True
        return False

    @check_rights
    def do_DELETE(self, context):
        """Manage DELETE request."""
        self._answer = ''
        code = client.NO_CONTENT
        try:
            item_name = paths.resource_from_path(self.path)
            with self._collection:
                items = self._collection.get_items(item_name)

                if len(items) and self.if_match(items):
                    # No ETag precondition or precondition verified, delete item
                    self._answer = xmlutils.delete(self.path, self._collection, context=context)

                elif not len(items):
                    # Item does not exist
                    code = client.NOT_FOUND
                else:
                    # No item or ETag precondition not verified, do not delete item
                    code = client.PRECONDITION_FAILED

        except Exception:
            log.exception("Failed DELETE for %s", self.path)
            code = client.BAD_REQUEST

        self.send_calypso_response(code, len(self._answer))
        if len(self._answer):
            self.send_header("Content-Type", "text/xml")
        self.end_headers()
        if len(self._answer):
            self.wfile.write(self._answer)

    @check_rights
    def do_MKCALENDAR(self, context):
        """Manage MKCALENDAR request."""
        self.send_calypso_response(client.CREATED, 0)
        self.end_headers()

    def do_OPTIONS(self):
        """Manage OPTIONS request."""
        self.send_calypso_response(client.OK, 0)
        self.send_header(
            "Allow", "DELETE, HEAD, GET, MKCALENDAR, "
            "OPTIONS, PROPFIND, PUT, REPORT")
        self.send_header("DAV", "1, access-control, calendar-access, addressbook")
        self.end_headers()

    @check_rights
    def do_PROPFIND(self, context):
        """Manage PROPFIND request."""
        try:
            xml_request = self.xml_request
            log.debug("PROPFIND %s", xml_request)
            depth = self.headers.get("depth", "infinity")
            if depth != "infinity":
                with self._collection:
                    self._answer = xmlutils.propfind(
                        self.path, xml_request, self._collection,
                        depth, context)
                status = client.MULTI_STATUS
            else:
                self._answer = xmlutils.propfind_deny()
                status = client.FORBIDDEN

            if len(self._answer) < 100:
                log.debug("PROPFIND ANSWER %s", self._answer)
            else:
                log.debug("PROPFIND ANSWER len %d", len(self._answer))

            self.send_calypso_response(status, len(self._answer))
            self.send_header("DAV", "1, calendar-access")
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(self._answer)
        except Exception:
            log.exception("Failed PROPFIND for %s", self.path)
            self.send_calypso_response(client.BAD_REQUEST, 0)
            self.end_headers()

    @check_rights
    def do_SEARCH(self, context):
        """Manage SEARCH request."""
        try:
            self.send_calypso_response(client.NO_CONTENT, 0)
            self.end_headers()
        except Exception:
            log.exception("Failed SEARCH for %s", self.path)
            self.send_calypso_response(client.BAD_REQUEST, 0)
            self.end_headers()

    @check_rights
    def do_PUT(self, context):
        """Manage PUT request."""

        code = client.CREATED
        etag = None
        try:
            item_name = paths.resource_from_path(self.path)
            with self._collection:
                items = self._collection.get_items(item_name)
                if not len(items) or self.if_match(items):

                    # PUT allowed in 3 cases
                    # Case 1: No item and no ETag precondition: Add new item
                    # Case 2: Item and ETag precondition verified: Modify item
                    # Case 3: Item and no Etag precondition: Force modifying item
                    webdav_request = self._decode(self.xml_request)
                    new_item = xmlutils.put(self.path, webdav_request, self._collection, context=context)

                    log.debug("item_name %s new_name %s", item_name, new_item.name)
                    etag = new_item.etag
                    #log.debug("replacement etag %s", etag)

                    code = client.CREATED
                    etag = new_item.etag
                else:
                    #log.debug("Precondition failed")
                    # PUT rejected in all other cases
                    code = client.PRECONDITION_FAILED

        except Exception:
            log.exception('Failed PUT for %s', self.path)
            code = client.BAD_REQUEST

        self.send_calypso_response(code, 0)
        if etag:
            self.send_header('ETag', etag)
        self.end_headers()

    @check_rights
    def do_REPORT(self, context):
        """Manage REPORT request."""
        try:
            xml_request = self.xml_request
            log.debug("REPORT %s %s", self.path, xml_request)
            with self._collection:
                self._answer = xmlutils.report(self.path, xml_request, self._collection)

            if len(self._answer) < 100:
                log.debug("REPORT ANSWER %s" % self._answer)
            else:
                log.debug("REPORT ANSWER %d" % len(self._answer))
            self.send_calypso_response(client.MULTI_STATUS, len(self._answer))
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(self._answer)
        except Exception:
            log.exception("Failed REPORT for %s", self.path)
            self.send_calypso_response(client.BAD_REQUEST, 0)
            self.end_headers()

    # pylint: enable=C0103
