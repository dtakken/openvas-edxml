#!/usr/bin/env python
# -*- coding: utf-8 -*-
from IPy import IP

from edxml.event import EventElement
from openvas_edxml.brick import OpenVASBrick

from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkBrick


class OpenVasErrorTranscoder(XmlTranscoder):

    TYPE_MAP = {
        '.': 'org.openvas.scan.error'
    }

    PROPERTY_MAP = {
        'org.openvas.scan.error': {
            '../../../report/@id': 'scan-id',
            'host': 'host',
            'nvt/@oid': 'nvt-oid',
            'nvt/name': 'nvt-name',
            'description': 'message',
        }
    }

    TYPE_DESCRIPTIONS = {
        'org.openvas.scan.error': 'Failed OpenVAS test'
    }

    TYPE_DISPLAY_NAMES = {
        'org.openvas.scan.error': ['OpenVAS test failure']
    }

    TYPE_SUMMARIES = {
        'org.openvas.scan.error': 'OpenVAS failure while testing [[host-ipv4]][[host-ipv6]]'
    }

    TYPE_STORIES = {
        'org.openvas.scan.error':
            'During OpenVAS scan [[scan-id]], host [[host-ipv4]][[host-ipv6]] was tested using a '
            'plugin titled [[nvt-name]] (NVT OID [[nvt-oid]]). '
            'Unfortunately, the test failed with error message "[[message]]".'
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan.error': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'nvt-oid': ComputingBrick.OBJECT_OID,
            'nvt-name': OpenVASBrick.OBJECT_NVT_NAME,
            'message': OpenVASBrick.OBJECT_ERROR_MESSAGE,
        }
    }

    TYPE_OPTIONAL_PROPERTIES = {
        'org.openvas.scan.error': ['host-ipv4', 'host-ipv6']
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan.error': {
            'scan-id': 'scan UUID',
            'host-ipv4': 'target host (IPv4)',
            'host-ipv6': 'target host (IPv6)',
            'nvt-oid': 'OpenVAS plugin ID',
            'nvt-name': 'OpenVAS plugin name',
        }
    }

    TYPE_HASHED_PROPERTIES = {
        'org.openvas.scan.error': ['scan-id', 'host-ipv4', 'host-ipv6', 'nvt-oid']
    }

    TYPE_AUTO_REPAIR_NORMALIZE = {
        'org.openvas.scan.error': ['host-ipv4', 'host-ipv6']
    }

    TYPE_AUTO_REPAIR_DROP = {
        'org.openvas.scan.error': ['host-ipv4', 'host-ipv6']
    }

    PARENTS_CHILDREN = [
        ['org.openvas.scan', 'that produced', 'org.openvas.scan.error']
    ]

    CHILDREN_SIBLINGS = [
        ['org.openvas.scan.error', 'produced by', 'org.openvas.scan']
    ]

    PARENT_MAPPINGS = {
        'org.openvas.scan.error': {
            'scan-id': 'id'
        }
    }

    def post_process(self, event, input_element):

        parsed = IP(event.get_any('host'))

        # We assign the host IP address to both the IPv4 and IPv6
        # property. Either one of these will be invalid and will
        # be automatically removed by the EDXML transcoder mediator,
        # provided that it is configured to do so.
        event['host-ipv4'] = parsed.strFullsize()
        event['host-ipv6'] = parsed.strFullsize()

        del event['host']

        yield event

        # While we use the OpenVasHostTranscoder to generate events that
        # list the executed NVTs, these lists are incomplete. The host details
        # section in OpenVAS reports only contains NVT that were successfully
        # executed without yielding any results. To complete the NVT lists, we
        # need to generate an org.openvas.scan.nvt event from each failed test
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

        error = super().create_event_type(event_type_name, ontology)

        # Associate OpenVAS plugins with the vulnerability concept. This models
        # the fact that OpenVAS plugin IODs are unique identifiers of a particular
        # issue.
        error['nvt-oid'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 10)

        # Associate NVT names with the vulnerability concept. Confidence is
        # lower though as NVT names are not unique.
        error['nvt-name'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, 5)

        # The IP address of the host is an identifier of a computer.
        error['host-ipv4'].identifies(ComputingBrick.CONCEPT_COMPUTER, 7)
        error['host-ipv6'].identifies(ComputingBrick.CONCEPT_COMPUTER, 7)

        # Relate the NVT OID to its name
        error['nvt-oid'].relate_intra('is named', 'nvt-name') \
            .because('an OpenVAS result of plugin [[nvt-oid]] is named [[nvt-name]]')

        return error
