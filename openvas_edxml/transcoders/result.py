#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lxml import etree

import re
from IPy import IP

from openvas_edxml.brick import OpenVASBrick

from edxml.ontology import EventProperty
from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.generic import GenericBrick
from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkBrick
from edxml_bricks.computing.security import SecurityBrick


class OpenVasResultTranscoder(XmlTranscoder):

  TYPES = ['org.openvas.scan.result']

  TYPE_MAP = {'/get_reports_response/report/report/results/result': 'org.openvas.scan.result'}

  XPATH_MAP = {
    './@id':                                                              'id',
    '../../../report/@id':                                                'scan-id',
    './nvt/name':                                                         'nvt-name',
    './nvt/family':                                                       'nvt-family',
    './nvt/cvss_base':                                                    'cvss-score',
    './nvt/@oid':                                                         'nvt-oid',
    './creation_time':                                                    'time',
    './severity':                                                         'severity',
    './threat':                                                           'threat',
    './host':                                                             'host-ipv4',
    './port':                                                             'port',
    './qod/type':                                                         'qod-type',
    './qod/value':                                                        'qod-value',
    './description':                                                      'description',
    './detection/result/details/detail/value[re:test(., "^cpe:/", "i")]': 'cpe_detect',
    ('ws_normalize('
     '  openvas_normalize('
     '    findall(./nvt/tags, "(?:^|\|)summary=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'summary',
    ('ws_normalize('
     '  ctrl_strip('
     '    findall(./nvt/tags, "(?:^|\|)cvss_base_vector=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'cvss-base',
    ('ws_normalize('
     '  openvas_normalize('
     '    findall(./nvt/tags, "(?:^|\|)solution=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'solution',
    ('ws_normalize('
     '  ctrl_strip('
     '    findall(./nvt/tags, "(?:^|\|)solution_type=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'solution-type',
    ('ws_normalize('
     '  ctrl_strip('
     '    findall(./nvt/xref, "(?:^|[, ])URL:((?:.(?!,[ ]*))+.)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'xref',
    ('ws_normalize('
     '  openvas_normalize('
     '    findall(./nvt/tags, "(?:^|\|)insight=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'insight',
    ('ws_normalize('
     '  openvas_normalize('
     '    findall(./nvt/tags, "(?:^|\|)affected=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'affected',
    ('ws_normalize('
     '  openvas_normalize('
     '    findall(./nvt/tags, "(?:^|\|)impact=([^|]*)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'impact',
    ('ws_normalize('
     '  ctrl_strip('
     '    findall(./nvt/cve, "(?:^|[, ])(CVE-(?:.(?!,[ ]*))+.)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'cve',
    ('ws_normalize('
     '  ctrl_strip('
     '    findall(./nvt/bid, "(?:^|[, ])((?:\d(?!,[ ]*))+.)", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'bid',
    ('ws_normalize('
     '  ctrl_strip('
     '    findall(./description, "cpe:/\S+", %d)'
     '  )'
     ')') % re.IGNORECASE:                                                'description_cpe',
  }

  TYPE_DESCRIPTIONS = {
    'org.openvas.scan.result': 'OpenVAS vulnerability detection result'
  }

  TYPE_DISPLAY_NAMES = {
    'org.openvas.scan.result': ['detected vulnerability', 'detected vulnerabilities']
  }

  TYPE_SUMMARIES = {
    'org.openvas.scan.result': 'OpenVAS result: [[nvt-family]]'
  }

  TYPE_STORIES = {
    'org.openvas.scan.result': (
      'On [[FULLDATETIME:time]], OpenVAS detected a possible security issue related to host '
      '{[[host-ipv4]]}{[[host-ipv6]]}{, on port [[port]]}.'
      ' The issue was found by an OpenVAS plugin from the [[nvt-family]] family, titled "[[nvt-name]]".'
      '{ OpenVAS indicates a severity of [[severity]], threat level [[threat]].}'
      '{ The CVSS base score is [[cvss-score]] (base vector [[cvss-base]]).}'
      '{ The result is summarized as:\n"[[summary]]"\n}'
      ' The problem{ affects [[affected]] and} is with [[qod-value]]% certainty applicable to this host, '
      'based on [[qod-type]].'
      '{ The impact is described as follows:\n"[[impact]]"\n}'
      '{ Technical details about the problem:\n"[[insight]]"\n}'
      '{ Concerning the solution ([[solution-type]]), the OpenVAS plugin authors say:\n"[[solution]]"}'
      '{\nAdditional information about the issue can be found [[URL:xref,here]].}'
      '{\nThe detection process revealed that the host is probably'
      '{ a [[device]] device}{ running [[os]]}.}'
      '{\nScanning results suggest that the host has the following application(s) installed: [[application]].}'
    )
  }

  TYPE_PROPERTIES = {
    'org.openvas.scan.result': {
      'id':            ComputingBrick.OBJECT_UUID,
      'scan-id':       ComputingBrick.OBJECT_UUID,
      'time':          GenericBrick.OBJECT_DATETIME,
      'host-ipv4':     NetworkBrick.OBJECT_HOST_IPV4,
      'host-ipv6':     NetworkBrick.OBJECT_HOST_IPV4,
      'port':          NetworkBrick.OBJECT_HOST_PORT,
      'nvt-name':      OpenVASBrick.OBJECT_NVT_NAME,
      'nvt-family':    OpenVASBrick.OBJECT_NVT_FAMILY,
      'nvt-oid':       OpenVASBrick.OBJECT_NVT_OID,
      'severity':      OpenVASBrick.OBJECT_SEVERITY,
      'threat':        OpenVASBrick.OBJECT_THREAT,
      'summary':       OpenVASBrick.OBJECT_SUMMARY,
      'affected':      OpenVASBrick.OBJECT_AFFECTS,
      'impact':        OpenVASBrick.OBJECT_IMPACT,
      'insight':       OpenVASBrick.OBJECT_INSIGHT,
      'qod-type':      OpenVASBrick.OBJECT_QOD_TYPE,
      'qod-value':     OpenVASBrick.OBJECT_QOD_VALUE,
      'solution':      OpenVASBrick.OBJECT_SOLUTION,
      'solution-type': OpenVASBrick.OBJECT_SOLUTION_TYPE,
      'xref':          OpenVASBrick.OBJECT_XREF,
      'application':   SecurityBrick.OBJECT_CPE_URI,
      'device':        SecurityBrick.OBJECT_CPE_URI,
      'os':            SecurityBrick.OBJECT_CPE_URI,
      'cvss-base':     SecurityBrick.OBJECT_CVSS_VECTOR,
      'cvss-score':    SecurityBrick.OBJECT_CVSS_SCORE,
      'cve':           SecurityBrick.OBJECT_CVE,
      'bid':           SecurityBrick.OBJECT_BID
    }
  }

  TYPE_PROPERTY_DESCRIPTIONS = {
    'org.openvas.scan.result': {
      'id':            'result UUID',
      'scan-id':       'scan UUID',
      'time':          'detection time',
      'host-ipv4':     'scanned host (IPv4)',
      'host-ipv6':     'scanned host (IPv6)',
      'port':          'scanned port',
      'nvt-name':      'plugin name',
      'nvt-family':    'plugin family',
      'nvt-oid':       'OpenVAS plugin',
      'qod-type':      'QoD type',
      'qod-value':     'QoD value',
      'xref':          'cross reference',
      'affected':      'affected systems',
      'application':   'detected application',
      'device':        'detected device',
      'os':            'detected OS',
      'cvss-base':     'CVSS base vector',
      'cvss-score':    'CVSS base score',
      'cve':           'associated CVE',
      'bid':           'associated BID'
    }
  }

  TYPE_PROPERTY_MERGE_STRATEGIES = {
    'org.openvas.scan.result': {
      'id':         EventProperty.MERGE_MATCH,
    }
  }

  PARENTS_CHILDREN = [
    ['org.openvas.scan', 'yielding', 'org.openvas.scan.result']
  ]

  CHILDREN_SIBLINGS = [
    ['org.openvas.scan.result', 'detected in', 'org.openvas.scan']
  ]

  PARENT_MAPPINGS = {
    'org.openvas.scan.result': {
      'scan-id': 'id'
    }
  }

  def __init__(self):
    super(OpenVasResultTranscoder, self).__init__()
    ns = etree.FunctionNamespace(None)
    ns['openvas_normalize'] = self._OpenVasNormalizeString

  @staticmethod
  def _OpenVasNormalizeString(Context, Strings):
    """

    This function is available as an XPath function named 'openvas_normalize', in
    the global namespace. It expects either a single string or a list of
    strings as input. It returns the input after stripping all of that typical
    OpenVAS cruft that you can find in various XML fields, like line wrapping or
    ASCII art list markup.
    Example::

      'openvas_normalize(string(./some/subtag))'

    Args:
        Context: lxml function context
        Strings (Union[unicode, List[unicode]): Input strings

    Returns:
      (Union[unicode, List[unicode])

    """
    OutStrings = []
    if Strings:
      if not isinstance(Strings, list):
        Strings = [Strings]
      for String in Strings:
        String = String.replace('\n', '\\n')

        OutStrings.append(String)
    return OutStrings if isinstance(Strings, list) else OutStrings[0]

  def PostProcess(self, Event):

    pluginOid = Event.getAny('nvt-oid')

    if pluginOid == '1.3.6.1.4.1.25623.1.0.105937':
      # This plugin aggregates OS detection results from other
      # plugins that do not yield any results of their own. We only
      # want to get the best matching OS.
      results = re.match(r'Best matching OS:(.*)Other OS detections', Event.getAny('description', ''), re.DOTALL)
      if results:
        Event['description_cpe'] = []
        for cpe in re.findall(r'cpe:/\S+', results.group(1)):
          Event['description_cpe'] += cpe

    # The tags and description fields may contain fairy long descriptions
    # of what has been found. We combine them as event content.
    Event.SetContent(
      '\n'.join(
        Event.get('description', []) +
        Event.get('tags', [])
      )
    )

    del Event['description']
    del Event['tags']

    # Ports are strings like 443/tcp. Split them
    # out in a port number and protocol.
    port, protocol = Event.get('port', ['/'])[0].split('/')

    try:
      int(port)
    except ValueError:
      # Not a port number.
      del Event['port']

    # The host may be an IPv4 or IPv6 address. Determine
    # what it is and store in the correct property.
    try:
      Parsed = IP(Event['host-ipv4'][0])
    except ValueError:
      # The IPy fails on zone identifiers in IPv6 addresses, strip them.
      Parsed = IP(Event['host-ipv4'][0].split('%')[0])
    if Parsed.version() == 6:
      Event['source-ipv6'] = Parsed.strFullsize()
      del Event['source-ipv4']

    # Populate event properties depending on what the
    # detected CPEs represent. Note that some plugins
    # put CPEs in the detect tag, while others put it
    # in the description tag. Here, we combine both.
    for cpe in Event['cpe_detect'] + Event['description_cpe']:
      if cpe.startswith('cpe:/a:'):
        # Vulnerability concerns an application.
        Event['application'] += [cpe]
      elif cpe.startswith('cpe:/h:'):
        # Vulnerability concerns a hardware device.
        Event['device'] += [cpe]
      elif cpe.startswith('cpe:/o:'):
        # Vulnerability concerns an operating system.
        Event['os'] += [cpe]

    del Event['cpe_detect']
    del Event['description_cpe']

    yield Event

  def GenerateEventTypes(self):

    for EventTypeName, EventTypeInstance in XmlTranscoder.GenerateEventTypes(self):
      if EventTypeName == 'org.openvas.scan.result':
        Result = EventTypeInstance

      # Associate OpenVAS plugins with the vulnerability concept. This models
      # the fact that OpenVAS plugin IODs are unique identifiers of a particular
      # issue.
      Result['nvt-oid'].Identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 1)

      # OpenVAS plugins may refer to multiple external vulnerability identifiers,
      # like CVE numbers. So, OpenVAS plugins conceptually detect meta-vulnerabilities,
      # which include any of multiple CVE. OpenVAS does not tell us which CVE was
      # actually detected, so we cannot include the CVE in the computer concept as
      # a vulnerability of a particular computer. We will associate them with the
      # vulnerability concept. The NVT IOD should be the strongest identifier of
      # the vulnerability concept, CVE and BID are weaker because one CVE might be
      # referenced by multiple OpenVAS plugins.
      Result['cve'].Identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 0.9)
      Result['bid'].Identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 0.9)

      # The IP address of the host is an identifier of a computer.
      Result['host-ipv4'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.7)
      Result['host-ipv6'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.7)

      # The detected device, operating system and applications are properties
      # of a computer, but they are weak identifiers.
      Result['application'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.1)
      Result['device'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.1)
      Result['os'].Identifies(ComputingBrick.CONCEPT_COMPUTER, 0.1)

      # Create inter-concept relation between host IP addresses and en OpenVAS plugin,
      # indicating the the host is susceptible to the problem that the plugin detects.
      Result['host-ipv4'].RelateInter('is vulnerable to', 'nvt-oid')\
        .Because('OpenVAS plugin [[nvt-oid]] returned a positive result while scanning host [[host-ipv4]]')
      Result['host-ipv6'].RelateInter('is vulnerable to', 'nvt-oid')\
        .Because('OpenVAS plugin [[nvt-oid]] returned a positive result while scanning host [[host-ipv6]]')

      # Create intra-concept relations between the OpenVAS plugin and any associated vulnerability
      # identifiers, like CVE.
      Result['nvt-oid'].RelateIntra('checks for', 'cve')\
        .Because('OpenVAS plugin [[nvt-oid]] mentions CVE [[cve]]')
      Result['nvt-oid'].RelateIntra('checks for', 'bid')\
        .Because('OpenVAS plugin [[nvt-oid]] mentions BID [[bid]]')

      # Create intra-concept relations between the host IP and any detected OSes, devices
      # and applications.
      Result['host-ipv4'].RelateIntra('is', 'device')\
        .Because('OpenVAS found evidence that host [[host-ipv4]] is a [[device]]')
      Result['host-ipv6'].RelateIntra('is', 'device')\
        .Because('OpenVAS found evidence that host [[host-ipv6]] is a [[device]]')
      Result['host-ipv4'].RelateIntra('runs', 'os')\
        .Because('OpenVAS found evidence that host [[host-ipv4]] runs on [[os]]')
      Result['host-ipv6'].RelateIntra('runs', 'os')\
        .Because('OpenVAS found evidence that host [[host-ipv6]] runs on [[os]]')
      Result['host-ipv4'].RelateIntra('runs', 'application')\
        .Because('OpenVAS detected [[application]] running on host [[host-ipv4]]')
      Result['host-ipv6'].RelateIntra('runs', 'application')\
        .Because('OpenVAS detected [[application]] running on host [[host-ipv6]]')

      # Add a hint to relate scan results found by the same OpenVAS plugin and
      # results that concern the same host
      Result['nvt-oid'].HintSimilar('found by')
      Result['host-ipv4'].HintSimilar('concerning')
      Result['host-ipv6'].HintSimilar('concerning')

      yield EventTypeName, Result
