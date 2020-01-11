#!/usr/bin/env python
# -*- coding: utf-8 -*-
from urlparse import urlsplit
from lxml import etree

import re
from IPy import IP

from edxml.event import EventElement
from openvas_edxml.brick import OpenVASBrick
from openvas_edxml.transcoders.logger import log

from edxml.ontology import EventProperty
from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.generic import GenericBrick
from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkBrick
from edxml_bricks.computing.security import SecurityBrick


def post_process_port(port):
    # Ports are strings like 443/tcp. Split them
    # out in a port number and protocol.
    port, protocol = port.split('/')

    # Newer OpenVAS versions append a description to the port,
    # like '80/tcp (IANA: www-http)'. Strip it off.
    protocol, = protocol.split(' ')[0:1]

    try:
        int(port)
    except ValueError:
        # Not a port number.
        return None

    return '%s/%s' % (port, protocol)


def post_process_xref(xref):
    # The xrefs in OpenVAS reports often contain invalid URIs.
    # Remove these to prevent producing invalid events.
    scheme, netloc, path, qs, anchor = urlsplit(xref)
    if scheme == '':
        log.warning('XREF field contains Invalid URI (omitted): %s' % xref)
        return None
    return xref


class OpenVasResultTranscoder(XmlTranscoder):

    TYPE_MAP = {'.': 'org.openvas.scan.result'}

    PROPERTY_MAP = {
        'org.openvas.scan.result': {
            '@id': 'id',
            '../../../report/@id': 'scan-id',
            'nvt/name': 'nvt-name',
            'nvt/family': 'nvt-family',
            'nvt/cvss_base': 'cvss-score',
            'nvt/@oid': 'nvt-oid',
            'creation_time': 'time',
            'severity': 'severity',
            'threat': 'threat',
            'ws_normalize(host)': 'host-ipv4',
            'port': 'port',
            'qod/type': 'qod-type',
            'qod/value': 'qod-value',
            'description': 'description',
            ('ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\|)summary=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'summary',
            ('ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/tags, "(?:^|\|)cvss_base_vector=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'cvss-base',
            ('ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\|)solution=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'solution',
            ('ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/tags, "(?:^|\|)solution_type=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'solution-type',
            ('ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/xref, "(?:^|[, ])URL:((?:.(?!,[ ]*))+.)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'xref',
            ('ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\|)insight=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'insight',
            ('ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\|)affected=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'affected',
            ('ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\|)impact=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'impact',
            ('ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/cve, "(?:^|[, ])(CVE-(?:.(?!,[ ]*))+.)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'cve',
            ('ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/bid, "(?:^|[, ])((?:\d(?!,[ ]*))+.)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'bid',
        }
    }

    TYPE_DESCRIPTIONS = {
        'org.openvas.scan.result': 'OpenVAS vulnerability detection result'
    }

    TYPE_DISPLAY_NAMES = {
        'org.openvas.scan.result': ['vulnerability detection']
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
        )
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan.result': {
            'id': ComputingBrick.OBJECT_UUID,
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'port': NetworkBrick.OBJECT_HOST_PORT,
            'nvt-name': OpenVASBrick.OBJECT_NVT_NAME,
            'nvt-family': OpenVASBrick.OBJECT_NVT_FAMILY,
            'nvt-oid': ComputingBrick.OBJECT_OID,
            'severity': OpenVASBrick.OBJECT_SEVERITY,
            'threat': OpenVASBrick.OBJECT_THREAT,
            'summary': OpenVASBrick.OBJECT_SUMMARY,
            'affected': OpenVASBrick.OBJECT_AFFECTS,
            'impact': OpenVASBrick.OBJECT_IMPACT,
            'insight': OpenVASBrick.OBJECT_INSIGHT,
            'qod-type': OpenVASBrick.OBJECT_QOD_TYPE,
            'qod-value': OpenVASBrick.OBJECT_QOD_VALUE,
            'solution': OpenVASBrick.OBJECT_SOLUTION,
            'solution-type': OpenVASBrick.OBJECT_SOLUTION_TYPE,
            'xref': OpenVASBrick.OBJECT_XREF,
            'cvss-base': SecurityBrick.OBJECT_CVSS_VECTOR,
            'cvss-score': SecurityBrick.OBJECT_CVSS_SCORE,
            'cve': SecurityBrick.OBJECT_CVE,
            'bid': SecurityBrick.OBJECT_BID
        }
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan.result': {
            'id': 'result UUID',
            'scan-id': 'scan UUID',
            'time': 'detection time',
            'host-ipv4': 'scanned host (IPv4)',
            'host-ipv6': 'scanned host (IPv6)',
            'port': 'scanned port',
            'nvt-name': 'plugin name',
            'nvt-family': 'plugin family',
            'nvt-oid': 'OpenVAS plugin',
            'qod-type': 'QoD type',
            'qod-value': 'QoD value',
            'xref': 'cross reference',
            'affected': 'affected systems',
            'cvss-base': 'CVSS base vector',
            'cvss-score': 'CVSS base score',
            'cve': 'associated CVE',
            'bid': 'associated BID'
        }
    }

    TYPE_PROPERTY_MERGE_STRATEGIES = {
        'org.openvas.scan.result': {
            'nvt-oid': EventProperty.MERGE_MATCH,
            'host-ipv4': EventProperty.MERGE_MATCH,
            'host-ipv6': EventProperty.MERGE_MATCH,
            'port': EventProperty.MERGE_MATCH
        }
    }

    TYPE_PROPERTY_POST_PROCESSORS = {
        'org.openvas.scan.result': {
            'port': post_process_port,
            'xref': post_process_xref
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

    TYPE_ATTACHMENTS = {
        'org.openvas.scan.result': ['description', 'input-xml-element']
    }

    TYPE_ATTACHMENT_MEDIA_TYPES = {
        'org.openvas.scan.result': {
            'input-xml-element': 'application/xml'
        }
    }

    TYPE_ATTACHMENT_DISPLAY_NAMES = {
        'org.openvas.scan.result': {
            'input-xml-element': 'original OpenVAS data record'
        }
    }

    def __init__(self):
        super(OpenVasResultTranscoder, self).__init__()
        ns = etree.FunctionNamespace(None)
        ns['openvas_normalize'] = self._open_vas_normalize_string

    @staticmethod
    def _open_vas_normalize_string(context, strings):
        """

        This function is available as an XPath function named 'openvas_normalize', in
        the global namespace. It expects either a single string or a list of
        strings as input. It returns the input after stripping all of that typical
        OpenVAS cruft that you can find in various XML fields, like line wrapping or
        ASCII art list markup.
        Example::

          'openvas_normalize(string(./some/subtag))'

        Args:
            context: lxml function context
            strings (Union[unicode, List[unicode]): Input strings

        Returns:
          (Union[unicode, List[unicode])

        """
        out_strings = []
        if strings:
            if not isinstance(strings, list):
                strings = [strings]
            for string in strings:
                string = string.replace('\n', '\\n')

                out_strings.append(string)
        return out_strings if isinstance(strings, list) else out_strings[0]

    def post_process(self, event, input_element):

        event.set_attachments(
            {
                # The description field may contain fairy long descriptions
                # of what has been found. We store it as event attachment.
                'description': event.get_any('description', ''),
                # We also store the original OpenVAS XML element, allowing
                # us to re-process it using future transcoder versions even
                # when the original data is no longer available.
                'input-xml-element': etree.tostring(input_element)
            }
        )

        del event['description']

        # We assign the host IP address to both the IPv4 and IPv6
        # property. Either one of these will be invalid and will
        # be automatically removed by the EDXML transcoder mediator,
        # provided that it is configured to do so.
        event['host-ipv4'] = IP(event.get_any('host-ipv4'))
        event['host-ipv6'] = event['host-ipv4']

        yield event

        # While we use the OpenVasHostTranscoder to generate events that
        # list the executed NVTs, these lists are incomplete. The host details
        # section in OpenVAS reports only contains NVT that were successfully
        # executed without yielding any results. To complete the NVT lists, we
        # need to generate an org.openvas.scan.nvt event from each scan result
        # as well. This is what we do below. Note that the nvt-oid property has
        # its merge strategy set to 'add', which means that the full list of
        # executed NVTs can be readily aggregated from multiple org.openvas.scan.nvt
        # output events.

        nvt_event = EventElement(
            properties={},
            event_type_name='org.openvas.scan.nvt',
            source_uri=event.get_source_uri()
        )

        nvt_event.copy_properties_from(
            event,
            {
                'scan-id': 'scan-id',
                'host-ipv4': 'host-ipv4',
                'host-ipv6': 'host-ipv6',
                'nvt-oid': 'nvt-oid'
            }
        )

        yield nvt_event

    @classmethod
    def create_event_type(cls, event_type_name, ontology):

        result = super(OpenVasResultTranscoder, cls).create_event_type(event_type_name, ontology)

        # TODO: SDK does not automatically set this property to single valued
        # when associating with parent event type. Fix that.
        result['scan-id'].set_multi_valued(False)

        # Associate OpenVAS plugins with the vulnerability concept. This models
        # the fact that OpenVAS plugin IODs are unique identifiers of a particular
        # issue.
        result['nvt-oid'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 10)

        # We associate the NVT names with the vulnerability concept. Confidence is
        # lower than the OID association though as NVT names are not unique.
        result['nvt-name'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 5)

        # OpenVAS plugins may refer to multiple external vulnerability identifiers,
        # like CVE numbers. So, OpenVAS plugins conceptually detect meta-vulnerabilities,
        # which include any of multiple CVE. OpenVAS does not tell us which CVE was
        # actually detected, so we cannot include the CVE in the computer concept as
        # a vulnerability of a particular computer. We will associate them with the
        # vulnerability concept. The NVT IOD should be the strongest identifier of
        # the vulnerability concept, CVE and BID are weaker because one CVE might be
        # referenced by multiple OpenVAS plugins.
        result['cve'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 9)
        result['bid'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 9)

        # The IP address of the host is an identifier of a computer.
        result['host-ipv4'].identifies(ComputingBrick.CONCEPT_COMPUTER, 7)
        result['host-ipv6'].identifies(ComputingBrick.CONCEPT_COMPUTER, 7)

        # Create inter-concept relation between host IP addresses and en OpenVAS plugin,
        # indicating the the host is susceptible to the problem that the plugin detects.
        result['host-ipv4'].relate_inter('is vulnerable to', 'nvt-oid') \
            .because('OpenVAS plugin [[nvt-oid]] returned a positive result while scanning host [[host-ipv4]]')
        result['host-ipv6'].relate_inter('is vulnerable to', 'nvt-oid') \
            .because('OpenVAS plugin [[nvt-oid]] returned a positive result while scanning host [[host-ipv6]]')

        # Create intra-concept relations between the OpenVAS plugin and any associated vulnerability
        # identifiers, like CVE.
        result['nvt-oid'].relate_intra('checks for', 'cve') \
            .because('OpenVAS plugin [[nvt-oid]] mentions CVE [[cve]]')
        result['nvt-oid'].relate_intra('checks for', 'bid') \
            .because('OpenVAS plugin [[nvt-oid]] mentions BID [[bid]]')

        # Relate the NVT OID to its name
        result['nvt-oid'].relate_intra('is named', 'nvt-name') \
            .because('an OpenVAS result of plugin [[nvt-oid]] is named [[nvt-name]]')

        # Add a hint to relate scan results found by the same OpenVAS plugin and
        # results that concern the same host
        result['nvt-oid'].hint_similar('found by')
        result['host-ipv4'].hint_similar('concerning')
        result['host-ipv6'].hint_similar('concerning')

        return result
