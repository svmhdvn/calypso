# vim: set fileencoding=utf-8 :
"""Test matching filter handling """

import subprocess
import tempfile
import shutil
import unittest
import xml.etree.ElementTree as ET

from calypso.webdav import Collection
from calypso import xmlutils

from .testutils import CalypsoTestCase


class TestMatchFilterElement(CalypsoTestCase):
    test_vcal = "tests/data/import.vcalendar"

    def test_start_end(self):
        """
Check that the time-range parser accept ranges where start or stop is
missing.
"""
        valid_xml_request1 ="""
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <prop xmlns="DAV:">
  <getetag xmlns="DAV:"/>
  <resourcetype xmlns="DAV:"/>
 </prop>
 <filter xmlns="urn:ietf:params:xml:ns:caldav">
  <comp-filter xmlns="urn:ietf:params:xml:ns:caldav" name="VCALENDAR">
    <time-range xmlns="urn:ietf:params:xml:ns:caldav" start="20151021T201004Z"/>
  </comp-filter>
 </filter>
</calendar-query>
"""
        valid_xml_request2 ="""
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <prop xmlns="DAV:">
  <getetag xmlns="DAV:"/>
  <resourcetype xmlns="DAV:"/>
 </prop>
 <filter xmlns="urn:ietf:params:xml:ns:caldav">
  <comp-filter xmlns="urn:ietf:params:xml:ns:caldav" name="VCALENDAR">
    <time-range xmlns="urn:ietf:params:xml:ns:caldav" end="20151021T201004Z"/>
  </comp-filter>
 </filter>
</calendar-query>
"""
        invalid_xml_request1 ="""
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <prop xmlns="DAV:">
  <getetag xmlns="DAV:"/>
  <resourcetype xmlns="DAV:"/>
 </prop>
 <filter xmlns="urn:ietf:params:xml:ns:caldav">
  <comp-filter xmlns="urn:ietf:params:xml:ns:caldav" name="VCALENDAR">
    <time-range xmlns="urn:ietf:params:xml:ns:caldav"/>
  </comp-filter>
 </filter>
</calendar-query>
"""
        collection = Collection("")
        self.assertTrue(collection.import_file(self.test_vcal))
        self.assertEqual(len(collection.items), 1)

        # Tried calling do_REPORT() directly, but lacked the arguments
        # needed to get the CollectionHTTPHandler class working.  Use
        # match_filter() directly instead.
        truecount = 0
        for xml_request in [valid_xml_request1, valid_xml_request2]:
            root = ET.fromstring(xml_request)
            filter_element = root.find(xmlutils._tag("C", "filter"))
            for item in collection.items:
                answer = xmlutils.match_filter(item, filter_element)
                if answer:
                    truecount += 1
        # The text vcalendar entry is either before or after the cutoff point.
        self.assertEqual(truecount, 1)

        for xml_request in [invalid_xml_request1]:
            root = ET.fromstring(xml_request)
            filter_element = root.find(xmlutils._tag("C", "filter"))
            for item in collection.items:
                with self.assertRaisesRegex(ValueError, "time-range missing both start and stop attribute"):
                    xmlutils.match_filter(item, filter_element)
        # The text vcalendar entry is either before or after the cutoff point.

