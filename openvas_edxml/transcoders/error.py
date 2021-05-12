from edxml.event import EventElement
from openvas_edxml.brick import OpenVASBrick

from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkingBrick
from openvas_edxml.transcoders import post_process_ip


class OpenVasErrorTranscoder(XmlTranscoder):

    TYPE_MAP = {
        '.': 'org.openvas.scan.error'
    }

    PROPERTY_MAP = {
        'org.openvas.scan.error': {
            '../../../report/@id': 'scan-id',
            'host': ['host.ipv4', 'host.ipv6'],
            'nvt/@oid': 'nvt.oid',
            'nvt/name': 'nvt.name',
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
        'org.openvas.scan.error': 'OpenVAS failure while testing [[host.ipv4]][[host.ipv6]]'
    }

    TYPE_STORIES = {
        'org.openvas.scan.error':
            'During OpenVAS scan [[scan-id]], host [[host.ipv4]][[host.ipv6]] was tested using a '
            'plugin titled [[nvt.name]] (NVT OID [[nvt.oid]]). '
            'Unfortunately, the test failed with error message "[[message]]".'
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan.error': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'nvt.oid': ComputingBrick.OBJECT_OID,
            'nvt.name': OpenVASBrick.OBJECT_NVT_NAME,
            'message': OpenVASBrick.OBJECT_ERROR_MESSAGE,
        }
    }

    TYPE_UNIVERSALS_NAMES = {
        'org.openvas.scan.error': {
            'nvt.oid': 'nvt.name'
        }
    }

    TYPE_PROPERTY_CONCEPTS = {
        'org.openvas.scan.error': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8},
            # Associate OpenVAS plugins with the finding concept. This models
            # the fact that OpenVAS plugin IODs are unique identifiers of a particular
            # type of finding.
            'nvt.oid': {OpenVASBrick.CONCEPT_FINDING: 10},
            # We associate the NVT names with the finding concept. Confidence is
            # lower than the OID association though as NVT names are not unique.
            'nvt.name': {OpenVASBrick.CONCEPT_FINDING: 5},
        }
    }

    TYPE_PROPERTY_CONCEPTS_CNP = {
        'org.openvas.scan.error': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'nvt.name': {OpenVASBrick.CONCEPT_FINDING: 192},
        }
    }

    TYPE_PROPERTY_ATTRIBUTES = {
        'org.openvas.scan.error': {
            'nvt.oid': {
                OpenVASBrick.CONCEPT_FINDING: [
                    ComputingBrick.OBJECT_OID + ':openvas.plugin', 'OpenVAS detection plugin ID'
                ]
            }
        }
    }

    TYPE_OPTIONAL_PROPERTIES = {
        'org.openvas.scan.error': ['host.ipv4', 'host.ipv6']
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan.error': {
            'scan-id': 'scan UUID',
            'host.ipv4': 'target host (IPv4)',
            'host.ipv6': 'target host (IPv6)',
            'nvt.oid': 'OpenVAS plugin ID',
            'nvt.name': 'OpenVAS plugin name',
        }
    }

    TYPE_PROPERTY_POST_PROCESSORS = {
        'org.openvas.scan.error': {
            'host.ipv4': post_process_ip,
            'host.ipv6': post_process_ip,
        }
    }

    TYPE_HASHED_PROPERTIES = {
        'org.openvas.scan.error': ['scan-id', 'host.ipv4', 'host.ipv6', 'nvt.oid']
    }

    TYPE_AUTO_REPAIR_NORMALIZE = {
        'org.openvas.scan.error': ['host.ipv4', 'host.ipv6']
    }

    TYPE_AUTO_REPAIR_DROP = {
        'org.openvas.scan.error': ['host.ipv4', 'host.ipv6']
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

        yield event

        # While we use the OpenVasHostTranscoder to generate events that
        # list the executed NVTs, these lists are incomplete. The host details
        # section in OpenVAS reports only contains NVT that were successfully
        # executed without yielding any results. To complete the NVT lists, we
        # need to generate an org.openvas.scan.nvt event from each failed test
        # as well. This is what we do below. Note that the nvt.oid property has
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
                'host.ipv4': 'host.ipv4',
                'host.ipv6': 'host.ipv6',
                'nvt.oid': 'nvt.oid'
            }
        )

        yield nvt_event

    @classmethod
    def create_event_type(cls, event_type_name, ontology):

        error = super().create_event_type(event_type_name, ontology)

        # Relate the NVT OID to its name
        error['nvt.oid'].relate_intra('is named', 'nvt.name') \
            .because('an OpenVAS result of plugin [[nvt.oid]] is named [[nvt.name]]')

        return error
