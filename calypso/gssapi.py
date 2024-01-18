# -*- coding: utf-8 -*-
#
# This file is part of Calypso - CalDAV/CardDAV/WebDAV Server
# Copyright © 2016 Guido Günther <agx@sigxcpu.org>
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
Gssapi module.

This module handles kerberos authentication via gssapi
"""

import base64
import os
import calypso.acl
import calypso.config
import calypso.acl.nopwd as nopwd

# pylint: disable=F0401
try:
    import gssapi
except ImportError:
    gssapi = None
# pylint: disable=F0401

class Negotiate(object):
    def __init__(self, log):
        self.log = log
        self.servicename = calypso.config.get("server", "servicename", fallback=None)

    def enabled(self):
        """Check if GSSAPI negotiation is supported"""
        return gssapi and self.servicename

    def try_aaa(self, authorization, request, owner):
        """Perform authentication and authorization"""
        user, success = self.step(authorization, request)
        if success:
            return user, nopwd.has_right(owner, user, None)
        return None, False

    def step(self, authorization, request):
        """
        Try to authenticate the client and if succesful authenticate
        ourself to the client.
        """
        if not self.enabled():
            return None, False

        neg, challenge = authorization.split()
        if neg.lower().strip() != 'negotiate':
            return None, False

        self.log.debug("Negotiate header found, trying Kerberos")

        try:
            gssapi_name = gssapi.Name(self.servicename).canonicalize(gssapi.MechType.kerberos)
        except Exception as err:
            self.log.error("Invalid GSSAPI servicename='%s', please check the [server] section in the config file! GSSAPI error: %s", self.servicename, err)
            return None, False

        try:
            gssapi_creds = gssapi.Credentials(usage='accept', name=gssapi_name)
        except Exception as err:
            self.log.error("Failed to obtain kerberos credentials from the system keytab! GSSAPI error: %s", err)
            return None, False

        try:
            gssapi_ctx = gssapi.SecurityContext(creds=gssapi_creds, usage='accept')
        except Exception as err:
            self.log.error("Failed to create a GSSAPI security context for the given kerberos credentials! GSSAPI error: %s", err)
            return None, False

        try:
            gssapi_token = gssapi_ctx.step(base64.b64decode(challenge.strip()))
        except Exception as err:
            self.log.error("Failed to perform GSSAPI negotation! GSSAPI error: %s", err)
            return None, False

        # Client authenticated successfully, so authenticate to the client:
        request.queue_header("WWW-Authenticate", f"Negotiate {base64.b64encode(gssapi_token)}")
        user = str(gssapi_ctx.initiator_name)

        self.log.debug("GSSAPI negotiation success: found user %s", user)
        return user, True
