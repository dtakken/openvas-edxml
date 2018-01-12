#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

from IPy import IP
from dateutil.parser import parse

from openvas_edxml.brick import OpenVASBrick

from edxml.ontology import DataType
from edxml.ontology import EventProperty

from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.generic import GenericBrick
from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkBrick


class OpenVasReportTranscoder(XmlTranscoder):

  TYPES = ['org.openvas.scan']

  TYPE_MAP = {'/get_reports_response/report/report': 'org.openvas.scan'}

  XPATH_MAP = {
    './@id': 'id',
    '../task/name': 'name',
    './host/ip': 'host',
    './hosts/count': 'host-count',
    './vulns/count': 'vuln-count',
    './scan_start': 'time-start',
    './scan_end': 'time-end',
  }

  TYPE_DESCRIPTIONS = {
    'org.openvas.scan': 'OpenVAS vulnerability scan'
  }

  TYPE_DISPLAY_NAMES = {
    'org.openvas.scan': ['OpenVAS scan']
  }

  TYPE_SUMMARIES = {
    'org.openvas.scan': 'OpenVAS scan named "[[name]]"'
  }

  TYPE_STORIES = {
    'org.openvas.scan': (
      'On [[FULLDATETIME:time-start]] an OpenVAS vulnerability scan{ ([[name]])} was initiated, targeting '
      '[[host-count]] hosts. The scan was completed in [[DURATION:time-start,time-end]] yielding [[vuln-count]] '
      'findings{ and was assigned UUID [[id]]}.{ The IP addresses of the scan targets are [[MERGE:host-ipv4,host-ipv6]].}'
    )
  }

  TYPE_PROPERTIES = {
    'org.openvas.scan': {
      'id':         ComputingBrick.OBJECT_UUID,
      'name':       OpenVASBrick.OBJECT_SCAN_NAME,
      'host-ipv4':  NetworkBrick.OBJECT_HOST_IPV4,
      'host-ipv6':  NetworkBrick.OBJECT_HOST_IPV6,
      'host-count': GenericBrick.OBJECT_COUNT_LARGE,
      'vuln-count': GenericBrick.OBJECT_COUNT_LARGE,
      'time-start': GenericBrick.OBJECT_DATETIME,
      'time-end':   GenericBrick.OBJECT_DATETIME,
    }
  }

  TYPE_PROPERTY_DESCRIPTIONS = {
    'org.openvas.scan': {
      'id':         'OpenVAS UUID',
      'host-ipv4':  'target host (IPv4)',
      'host-ipv6':  'target host (IPv6)',
      'vuln-count': 'vulnerability count',
      'time-start': 'starting time',
      'time-end':   'completion time',
    }
  }

  TYPE_PROPERTY_MERGE_STRATEGIES = {
    'org.openvas.scan': {
      'id':         EventProperty.MERGE_MATCH,
      'host-ipv4':  EventProperty.MERGE_ADD,
      'host-ipv6':  EventProperty.MERGE_ADD,
      'host-count': EventProperty.MERGE_MAX,
      'vuln-count': EventProperty.MERGE_MAX,
      'time-end':   EventProperty.MERGE_MAX
    }
  }

  def GenerateEventTypes(self):

    for EventTypeName, EventTypeInstance in XmlTranscoder.GenerateEventTypes(self):
      if EventTypeName == 'org.openvas.scan':

        # The IP address of the scanned host is an identifier of a computer.
        EventTypeInstance['host-ipv4'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.7)
        EventTypeInstance['host-ipv6'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.7)

        yield EventTypeName, EventTypeInstance

  def PostProcess(self, Event):

    if not Event['time-end']:
      Event['time-end'] = Event['time-start']
      sys.stderr.write('This scan report is incomplete, its scan_end tag is empty.\n')

    # The hosts may be IPv4 or IPv6 addresses. Determine
    # what it is and store in the correct property.
    Event['host-ipv4'] = []
    Event['host-ipv6'] = []

    for Host in set(Event['host']):
      try:
        Parsed = IP(Host)
      except ValueError:
        # The IPy fails on zone identifiers in IPv6 addresses, strip them.
        Parsed = IP(Host.split('%')[0])
      if Parsed.version() == 4:
        Event['host-ipv4'] += [Parsed.strFullsize()]
      else:
        Event['host-ipv6'] += [Parsed.strFullsize()]

    del Event['host']

    yield Event
