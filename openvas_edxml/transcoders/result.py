from urllib.parse import urlsplit
from lxml import etree

import re

from edxml.event import EventElement
from openvas_edxml.brick import OpenVASBrick
from openvas_edxml.logger import log

from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.generic import GenericBrick
from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkingBrick
from edxml_bricks.computing.networking.http import HttpBrick
from edxml_bricks.computing.security import SecurityBrick
from openvas_edxml.transcoders import post_process_ip


def post_process_port(port):
    # Ports are strings like 443/tcp. Split them
    # out in a port number and protocol.
    port, protocol = port.split('/')

    # Newer OpenVAS versions append a description to the port,
    # like '80/tcp (IANA: www-http)'. Strip it off.
    protocol, = protocol.split(' ')[0:1]

    try:
        yield '%d/%s' % (int(port), protocol.upper())
    except ValueError:
        # Not a port number, we yield nothing.
        ...


def post_process_xref(xref):
    # The xrefs in OpenVAS reports often contain invalid URIs.
    # Remove these to prevent producing invalid events.
    scheme, netloc, path, qs, anchor = urlsplit(xref)
    if scheme == '':
        log.warning('XREF field contains Invalid URI (omitted): %s' % xref)
        return

    yield xref


def post_process_threat(threat):
    yield threat.lower()


class OpenVasResultTranscoder(XmlTranscoder):

    TYPES = ['org.openvas.scan.result']

    TYPE_MAP = {'.': 'org.openvas.scan.result'}

    PROPERTY_MAP = {
        'org.openvas.scan.result': {
            '@id': 'id',
            '../../../report/@id': 'scan-id',
            'nvt/name': 'nvt.name',
            'nvt/family': 'nvt.family',
            'nvt/cvss_base': 'cvss.score',
            'nvt/@oid': 'nvt.oid',
            'creation_time': 'time',
            'severity': 'severity',
            'threat': 'threat',
            'ws_normalize(host)': ['host.ipv4', 'host.ipv6'],
            'port': 'port',
            'qod/type': 'qod.type',
            'qod/value': 'qod.value',
            (r'ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/tags, "(?:^|\\|)cvss_base_vector=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'cvss.base',
            (r'ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/tags, "(?:^|\\|)solution_type=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'solution-type',
            (r'ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/xref, "(?:^|[, ])URL:((?:.(?!,[ ]*))+.)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'xref',
            (r'ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\\|)insight=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'insight',
            (r'ws_normalize('
             '  openvas_normalize('
             '    findall(./nvt/tags, "(?:^|\\|)impact=([^|]*)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'impact',
            (r'ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/cve, "(?:^|[, ])(CVE-(?:.(?!,[ ]*))+.)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'cve',
            (r'ws_normalize('
             '  ctrl_strip('
             '    findall(./nvt/bid, "(?:^|[, ])((?:\\d(?!,[ ]*))+.)", %d)'
             '  )'
             ')') % re.IGNORECASE: 'bid',

            # The last couple of entries are intended to be
            # moved into event attachments.
            'description': 'attachment-description',
            r'findall(./nvt/tags, "(?:^|\\|)summary=([^|]*)", %d)' % re.IGNORECASE: 'attachment-summary',
            r'findall(./nvt/tags, "(?:^|\\|)solution=([^|]*)", %d)' % re.IGNORECASE: 'attachment-solution',
            r'findall(./nvt/tags, "(?:^|\\|)affected=([^|]*)", %d)' % re.IGNORECASE: 'attachment-affected',
        }
    }

    TYPE_DESCRIPTIONS = {
        'org.openvas.scan.result': 'OpenVAS detection result'
    }

    TYPE_DISPLAY_NAMES = {
        'org.openvas.scan.result': ['OpenVAS finding']
    }

    TYPE_SUMMARIES = {
        'org.openvas.scan.result': 'OpenVAS result: [[nvt.family]]'
    }

    TYPE_STORIES = {
        'org.openvas.scan.result':
            'On [[date_time:time,second]], OpenVAS detected a possible security issue related to host '
            '{[[host.ipv4]]}{[[host.ipv6]]}{, on port [[port]]}.'
            ' The issue was found by an OpenVAS plugin from the [[nvt.family]] family, titled "[[nvt.name]]".'
            '{ OpenVAS indicates a severity of [[severity]], threat level [[threat]].}'
            '{ The CVSS base score is [[cvss.score]] (base vector [[cvss.base]]).}'
            ' The problem is with [[qod.value]]% certainty applicable to this host, '
            'based on [[qod.type]].'
            '{ The impact is described as follows:\n"[[impact]]"\n}'
            '{ Technical details about the problem:\n"[[insight]]"\n}'
            '{ Solution is of type([[solution-type]])"}'
            '{\nAdditional information about the issue can be found [[url:xref,here]].}'
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan.result': {
            'id': ComputingBrick.OBJECT_UUID,
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'port': NetworkingBrick.OBJECT_HOST_PORT,
            'nvt.name': OpenVASBrick.OBJECT_NVT_NAME,
            'nvt.family': OpenVASBrick.OBJECT_NVT_FAMILY,
            'nvt.oid': ComputingBrick.OBJECT_OID,
            'severity': OpenVASBrick.OBJECT_SEVERITY,
            'vulnerability-severity': OpenVASBrick.OBJECT_SEVERITY,
            'threat': OpenVASBrick.OBJECT_THREAT,
            'impact': OpenVASBrick.OBJECT_IMPACT,
            'insight': OpenVASBrick.OBJECT_INSIGHT,
            'qod.type': OpenVASBrick.OBJECT_QOD_TYPE,
            'qod.value': OpenVASBrick.OBJECT_QOD_VALUE,
            'solution-type': OpenVASBrick.OBJECT_SOLUTION_TYPE,
            'xref': HttpBrick.OBJECT_HTTP_URL,
            'cvss.base': SecurityBrick.OBJECT_CVSS_VECTOR,
            'cvss.score': SecurityBrick.OBJECT_CVSS_SCORE,
            'cve': SecurityBrick.OBJECT_CVE,
            'bid': SecurityBrick.OBJECT_BID
        }
    }

    TYPE_UNIVERSALS_NAMES = {
        'org.openvas.scan.result': {
            'nvt.oid': 'nvt.name'
        }
    }

    TYPE_UNIVERSALS_CONTAINERS = {
        'org.openvas.scan.result': {
            'nvt.name': 'nvt.family'
        }
    }

    TYPE_OPTIONAL_PROPERTIES = {
        'org.openvas.scan.result': [
            'host.ipv4', 'host.ipv6', 'port', 'xref', 'cvss.base', 'cvss.score', 'cve', 'bid',
            'impact', 'insight', 'solution-type', 'vulnerability-severity'
        ]
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan.result': {
            'id': 'result UUID',
            'scan-id': 'scan UUID',
            'time': 'detection time',
            'host.ipv4': 'scanned host (IPv4)',
            'host.ipv6': 'scanned host (IPv6)',
            'port': 'scanned port',
            'nvt.name': 'plugin name',
            'nvt.family': 'plugin family',
            'nvt.oid': 'OpenVAS plugin',
            'qod.type': 'QoD type',
            'qod.value': 'QoD value',
            'xref': 'cross reference',
            'cvss.base': 'CVSS base vector',
            'cvss.score': 'CVSS base score',
            'cve': 'associated CVE',
            'bid': 'associated BID'
        }
    }

    TYPE_MULTI_VALUED_PROPERTIES = {
        'org.openvas.scan.result': ['xref', 'cve', 'bid']
    }

    TYPE_HASHED_PROPERTIES = {
        'org.openvas.scan.result': ['scan-id', 'nvt.oid', 'host.ipv4', 'host.ipv6', 'port']
    }

    TYPE_PROPERTY_POST_PROCESSORS = {
        'org.openvas.scan.result': {
            'port': post_process_port,
            'xref': post_process_xref,
            'host.ipv4': post_process_ip,
            'host.ipv6': post_process_ip,
            'threat': post_process_threat,
        }
    }

    TYPE_AUTO_REPAIR_NORMALIZE = {
        'org.openvas.scan.result': ['cve', 'time', 'host.ipv4', 'host.ipv6']
    }

    TYPE_AUTO_REPAIR_DROP = {
        'org.openvas.scan.result': ['host.ipv4', 'host.ipv6']
    }

    PARENTS_CHILDREN = [
        ['org.openvas.scan', 'yielding', 'org.openvas.scan.result']
    ]

    CHILDREN_SIBLINGS = [
        ['org.openvas.scan.result', 'produced by', 'org.openvas.scan']
    ]

    PARENT_MAPPINGS = {
        'org.openvas.scan.result': {
            'scan-id': 'id'
        }
    }

    TYPE_PROPERTY_CONCEPTS = {
        'org.openvas.scan.result': {

            # The IP address of the host is an identifier of a computer. IP addresses
            # are not always unique, so we will not make them really strong identifiers.
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8},
            # Open ports are weak identifiers of computers.
            'port': {ComputingBrick.CONCEPT_COMPUTER: 0},

            # Associate OpenVAS plugins with the finding concept. This models
            # the fact that OpenVAS plugin IODs are unique identifiers of a particular
            # type of finding.
            'nvt.oid': {OpenVASBrick.CONCEPT_FINDING: 10},
            # We associate the NVT names with the finding concept. Confidence is
            # lower than the OID association though as NVT names are not unique.
            'nvt.name': {OpenVASBrick.CONCEPT_FINDING: 5},
            # Associate more properties to the finding concept, all weak identifiers.
            'nvt.family': {OpenVASBrick.CONCEPT_FINDING: 0},
            'severity': {OpenVASBrick.CONCEPT_FINDING: 0},
            'threat': {OpenVASBrick.CONCEPT_FINDING: 0},
            'impact': {OpenVASBrick.CONCEPT_FINDING: 0},
            'insight': {OpenVASBrick.CONCEPT_FINDING: 0},
            'solution-type': {OpenVASBrick.CONCEPT_FINDING: 0},
            'xref': {OpenVASBrick.CONCEPT_FINDING: 0},
            'qod.type': {OpenVASBrick.CONCEPT_FINDING: 0},
            'qod.value': {OpenVASBrick.CONCEPT_FINDING: 0},

            # The presence of some properties indicate that the finding is a vulnerability.
            # We will associate these with the vulnerability concept.
            # Note: OpenVAS plugins may refer to multiple external vulnerability identifiers,
            # like CVE numbers. So, OpenVAS plugins conceptually detect meta-vulnerabilities,
            # which include any of multiple CVE. OpenVAS does not tell us which CVE was
            # actually detected, so we cannot include the CVE in the computer concept as
            # a vulnerability of a particular computer.
            'cve': {SecurityBrick.CONCEPT_VULNERABILITY: 9},
            'bid': {SecurityBrick.CONCEPT_VULNERABILITY: 9},
            'vulnerability-severity': {SecurityBrick.CONCEPT_VULNERABILITY: 0},
            'cvss.base': {SecurityBrick.CONCEPT_VULNERABILITY: 0},
            'cvss.score': {SecurityBrick.CONCEPT_VULNERABILITY: 0},
        }
    }

    TYPE_PROPERTY_CONCEPTS_CNP = {
        'org.openvas.scan.result': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'nvt.name': {OpenVASBrick.CONCEPT_FINDING: 192},
            'nvt.family': {OpenVASBrick.CONCEPT_FINDING: 160},
        }
    }

    TYPE_PROPERTY_ATTRIBUTES = {
        'org.openvas.scan.result': {
            'nvt.oid': {
                OpenVASBrick.CONCEPT_FINDING: [
                    ComputingBrick.OBJECT_OID + ':openvas.plugin', 'OpenVAS detection plugin ID'
                ]
            }
        }
    }

    TYPE_ATTACHMENTS = {
        'org.openvas.scan.result': ['description', 'affected', 'solution', 'summary', 'input-xml-element']
    }

    TYPE_ATTACHMENT_MEDIA_TYPES = {
        'org.openvas.scan.result': {
            'input-xml-element': 'application/xml'
        }
    }

    TYPE_ATTACHMENT_DISPLAY_NAMES = {
        'org.openvas.scan.result': {
            'input-xml-element': 'original OpenVAS data record',
            'affected': 'finding scope',
            'summary': ['finding summary', 'finding summaries']
        }
    }

    def __init__(self):
        super().__init__()
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
            strings (Union[str, List[str]]): Input strings

        Returns:
          (Union[str, List[str]])

        """
        out_strings = []
        if strings:
            if not isinstance(strings, list):
                strings = [strings]
            for string in strings:
                out_strings.append(string.replace('\n', ''))
        return out_strings if isinstance(strings, list) else out_strings[0]

    def post_process(self, event, input_element):

        # We store the original OpenVAS XML element, allowing
        # us to re-process it using future transcoder versions even
        # when the original data is no longer available.
        event.attachments['input-xml-element']['input-xml-element'] = etree.tostring(input_element).decode('utf-8')

        # The description field may contain fairy long descriptions
        # of what has been found. We store it as event attachment.
        if event.get_any('attachment-description'):
            event.attachments['description']['description'] = event.get_any('attachment-description')

        # Some result fields like the description of affected systems and
        # proposed solution can be multi-line texts containing formatting
        # like itemized lists. We store these as attachments as well.
        if event.get_any('attachment-affected'):
            event.attachments['affected']['affected'] = event.get_any('attachment-affected')

        if event.get_any('attachment-solution'):
            event.attachments['solution']['solution'] = event.get_any('attachment-solution')

        if event.get_any('attachment-summary'):
            event.attachments['summary']['summary'] = event.get_any('attachment-summary')

        del event['attachment-description']
        del event['attachment-affected']
        del event['attachment-solution']
        del event['attachment-summary']

        # When severity > 0 we want the event to get associated
        # with a vulnerability rather than a finding. We do this
        # by conditionally copying the severity from a property
        # that is associated with a finding into a property that
        # is associated with a vulnerability.
        if float(event.get_any('severity', 0)) > 0:
            event['vulnerability-severity'] = event['severity']

        yield event

        # While we use the OpenVasHostTranscoder to generate events that
        # list the executed NVTs, these lists are incomplete. The host details
        # section in OpenVAS reports only contains NVT that were successfully
        # executed without yielding any results. To complete the NVT lists, we
        # need to generate an org.openvas.scan.nvt event from each scan result
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
                'time': 'time',
                'host.ipv4': 'host.ipv4',
                'host.ipv6': 'host.ipv6',
                'nvt.oid': 'nvt.oid'
            }
        )

        yield nvt_event

    @classmethod
    def create_event_type(cls, event_type_name, ontology):

        result = super().create_event_type(event_type_name, ontology)

        # Create inter-concept relation between host IP addresses and en OpenVAS plugin
        # OID, indicating the host has an OpenVAS finding associated with it.
        for ip in ('ipv4', 'ipv6'):
            result['nvt.oid'].relate_inter('was detected on host', 'host.' + ip) \
                .because(f"OpenVAS plugin [[nvt.oid]] returned a positive result while scanning host [[host.{ip}]]")

        # Relate the OpenVAS plugin OID to finding attributes
        result['nvt.oid'].relate_intra('has', 'nvt.name')\
            .because('OpenVAS plugin [[nvt.oid]] is named [[nvt.name]]')
        result['nvt.oid'].relate_intra('belongs to', 'nvt.family')\
            .because('OpenVAS plugin [[nvt.oid]] is from plugin family [[nvt.family]]')
        result['nvt.oid'].relate_intra('indicates', 'severity')\
            .because('OpenVAS plugin [[nvt.oid]] considers its issues to be of severity [[severity]]')
        result['nvt.oid'].relate_intra('indicates', 'threat')\
            .because('OpenVAS plugin [[nvt.oid]] considers its issues to have threat level [[threat]]')
        result['nvt.oid'].relate_intra('indicates', 'impact')\
            .because('OpenVAS plugin [[nvt.oid]] describes the impact of its issues as: [[impact]]')
        result['nvt.oid'].relate_intra('provides', 'insight')\
            .because('OpenVAS plugin [[nvt.oid]] provides threat insight: [[insight]]')
        result['nvt.oid'].relate_intra('suggests', 'solution-type')\
            .because('OpenVAS plugin [[nvt.oid]] suggests a solution of type [[solution-type]]')
        result['nvt.oid'].relate_intra('refers to', 'xref')\
            .because('OpenVAS plugin [[nvt.oid]] refers to [[xref]]')
        result['nvt.oid'].relate_intra('uses', 'qod.type')\
            .because('OpenVAS plugin [[nvt.oid]] detects issues using [[qod.type]]')
        result['nvt.oid'].relate_intra('indicates', 'qod.value')\
            .because('OpenVAS plugin [[nvt.oid]] indicates its detection quality as [[qod.value]]')

        # Relate the OpenVAS plugin OID to vulnerability attributes
        result['nvt.oid'].relate_intra('detects', 'cve')\
            .because('OpenVAS plugin [[nvt.oid]] detects vulnerability [[cve]]'),
        result['nvt.oid'].relate_intra('detects', 'bid')\
            .because('OpenVAS plugin [[nvt.oid]] detects vulnerability [[bid]]'),
        result['nvt.oid'].relate_intra('indicates', 'vulnerability-severity')\
            .because('OpenVAS plugin [[nvt.oid]] detects vulnerabilities of severity [[vulnerability-severity]]'),
        result['nvt.oid'].relate_intra('indicates', 'cvss.base')\
            .because('OpenVAS plugin [[nvt.oid]] indicates CVSS vector [[cvss.base]]'),
        result['nvt.oid'].relate_intra('indicates', 'cvss.score')\
            .because('OpenVAS plugin [[nvt.oid]] indicates CVSS score [[cvss.score]]'),

        # Relate the host IP to the port that it is apparently exposing
        for ip in ('ipv4', 'ipv6'):
            result['host.' + ip].relate_intra('exposes', 'port') \
                .because(f"OpenVAS detected that host [[host.{ip}]] exposes network port [[port]]")

        # Add a hint to relate scan results found by the same OpenVAS plugin and
        # results that concern the same host
        result['nvt.oid'].hint_similar('found by')
        result['host.ipv4'].hint_similar('concerning')
        result['host.ipv6'].hint_similar('concerning')

        return result
