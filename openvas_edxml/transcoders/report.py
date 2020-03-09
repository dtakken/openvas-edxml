#!/usr/bin/env python
# -*- coding: utf-8 -*-
from openvas_edxml.transcoders.logger import log
from IPy import IP

from openvas_edxml.brick import OpenVASBrick

from edxml.ontology import EventProperty
from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.generic import GenericBrick
from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkBrick


class OpenVasReportTranscoder(XmlTranscoder):

    TYPE_MAP = {'.': 'org.openvas.scan'}

    PROPERTY_MAP = {
        'org.openvas.scan': {
            '@id': 'id',
            '../task/name': 'name',
            'ports/port/host': 'host',
            'hosts/count': 'host-count',
            'vulns/count': 'vuln-count',
            'scan_start': 'time-start',
            'scan_end': 'time-end'
        }
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
        'org.openvas.scan':
            'On [[FULLDATETIME:time-start]] an OpenVAS vulnerability scan{ ([[name]])} was initiated, targeting '
            '[[host-count]] hosts. The scan was completed in [[DURATION:time-start,time-end]] yielding [[vuln-count]] '
            'findings{ and was assigned UUID [[id]]}.{ The IP addresses of the scan targets are '
            '[[MERGE:host-ipv4,host-ipv6]].}'
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan': {
            'id': ComputingBrick.OBJECT_UUID,
            'name': OpenVASBrick.OBJECT_SCAN_NAME,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'host-count': GenericBrick.OBJECT_COUNT_LARGE,
            'vuln-count': GenericBrick.OBJECT_COUNT_LARGE,
            'time-start': GenericBrick.OBJECT_DATETIME,
            'time-end': GenericBrick.OBJECT_DATETIME,
        }
    }

    TYPE_OPTIONAL_PROPERTIES = {
        'org.openvas.scan': ['host-ipv4', 'host-ipv6', 'time-end']
    }

    TYPE_MULTI_VALUED_PROPERTIES = {
        'org.openvas.scan': ['host-ipv4', 'host-ipv6']
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan': {
            'id': 'OpenVAS UUID',
            'host-ipv4': 'target host (IPv4)',
            'host-ipv6': 'target host (IPv6)',
            'vuln-count': 'vulnerability count',
            'time-start': 'starting time',
            'time-end': 'completion time',
        }
    }

    TYPE_PROPERTY_MERGE_STRATEGIES = {
        'org.openvas.scan': {
            'id': EventProperty.MERGE_MATCH,
            'host-ipv4': EventProperty.MERGE_ADD,
            'host-ipv6': EventProperty.MERGE_ADD,
            'host-count': EventProperty.MERGE_MAX,
            'vuln-count': EventProperty.MERGE_MAX,
            'time-end': EventProperty.MERGE_REPLACE
        }
    }

    TYPE_TIMESPANS = {'org.openvas.scan': ('time-start', 'time-end')}

    @classmethod
    def create_event_type(cls, event_type_name, ontology):

        scan = super(OpenVasReportTranscoder, cls).create_event_type(event_type_name, ontology)

        # The IP address of the scanned host is an identifier of a computer.
        scan['host-ipv4'].identifies(ComputingBrick.CONCEPT_COMPUTER, 7)
        scan['host-ipv6'].identifies(ComputingBrick.CONCEPT_COMPUTER, 7)

        return scan

    def post_process(self, event, input_element):

        if not event['time-end']:
            log.warning('This scan report is incomplete, its scan_end tag is empty.\n')

        event['host-ipv4'] = []
        event['host-ipv6'] = []

        for host in set(event['host']):
            # We assign the host IP address to both the IPv4 and IPv6
            # property. Either one of these will be invalid and will
            # be automatically removed by the EDXML transcoder mediator,
            # provided that it is configured to do so.
            parsed = IP(host)
            event['host-ipv4'].add(parsed)
            event['host-ipv6'].add(parsed)

        del event['host']

        yield event
