#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import codecs

from IPy import IP
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID, ExtensionOID, ExtensionNotFound

from edxml_bricks.computing.email import EmailBrick
from edxml_bricks.computing.security import SecurityBrick, CryptoBrick
from edxml_bricks.generic import GenericBrick
from edxml_bricks.geography import GeoBrick
from openvas_edxml.brick import OpenVASBrick

from edxml.ontology import EventProperty
from edxml.transcode.xml import XmlTranscoder

from edxml_bricks.computing.generic import ComputingBrick
from edxml_bricks.computing.networking.generic import NetworkBrick
from openvas_edxml.logger import log
from openvas_edxml.transcoders import post_process_ip


class OpenVasHostTranscoder(XmlTranscoder):

    # Note how we extract events from host details in two different ways. Either we
    # make the XPath expression yield one hit for all <detail> children of a host, or
    # we make it match each individual <detail> child.
    # The choice is determined in part by the desired structure of the output events.
    # Processing performance is another factor. Using a single complex XPath to output
    # one event can be way faster than outputting many colliding physical instances of
    # a single logical event.

    TYPE_MAP = {
        # We extract one event per host listing executed NVTs
        'detail/name[text() = "EXIT_CODE"]/../..': 'org.openvas.scan.nvt',
        # We extract one event per detail containing detected applications
        'detail/name[starts-with(text(),"cpe:/a:")]/..': 'org.openvas.scan.application-detection',
        # We extract one event per detail containing OS detections
        'detail/name[starts-with(text(),"cpe:/o:")]/..': 'org.openvas.scan.os-detection',
        # We extract one event per host containing SSL certificate details
        'detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.103692"]/../..': 'org.openvas.scan.ssl-certificate',
        # We extract one event per host containing open TCP/IP ports
        'detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.900239"]/../../..': 'org.openvas.scan.open-ports',
        # We extract one event per detail listing routers extracted from TraceRoute results
        'detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.51662"]/../..': 'org.openvas.scan.routers',
    }

    PROPERTY_MAP = {
        'org.openvas.scan.nvt': {
            '../../@id': 'scan-id',
            'ip': ['host-ipv4', 'host-ipv6'],
            'detail/name[text() = "EXIT_CODE"]/../source/name': 'nvt-oid',
        },
        'org.openvas.scan.application-detection': {
            '../../@id': 'scan-id',
            '../ip': ['host-ipv4', 'host-ipv6'],
            'name': 'application',
            'value': 'port',
        },
        'org.openvas.scan.os-detection': {
            '../../@id': 'scan-id',
            '../ip': ['host-ipv4', 'host-ipv6'],
            'name': 'os',
        },
        'org.openvas.scan.ssl-certificate': {
            '../../@id': 'scan-id',
            'ip|../ip': ['host-ipv4', 'host-ipv6'],
            'value': 'certificates',
        },
        'org.openvas.scan.open-ports': {
            '../../@id': 'scan-id',
            'ip|../ip': ['host-ipv4', 'host-ipv6'],
            'detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.900239"]/../../value': 'port',
        },
        'org.openvas.scan.routers': {
            '../../@id': 'scan-id',
            'value': 'host'
        }
    }

    TYPE_DESCRIPTIONS = {
        'org.openvas.scan.nvt': 'List of tests performed during an OpenVAS scan',
        'org.openvas.scan.application-detection': 'Application detected during an OpenVAS scan',
        'org.openvas.scan.os-detection': 'Operating system detected during an OpenVAS scan',
        'org.openvas.scan.ssl-certificate': 'SSL certificate detected during an OpenVAS scan',
        'org.openvas.scan.open-ports': 'List of open TCP/IP ports detected during an OpenVAS scan',
        'org.openvas.scan.routers': 'Network routers detected during an OpenVAS scan',
    }

    TYPE_DISPLAY_NAMES = {
        'org.openvas.scan.nvt': ['OpenVAS test listing'],
        'org.openvas.scan.application-detection': ['detected application'],
        'org.openvas.scan.os-detection': ['detected operating system'],
        'org.openvas.scan.ssl-certificate': ['discovered SSL certificate'],
        'org.openvas.scan.open-ports': ['detected open port listing'],
        'org.openvas.scan.routers': ['discovered router listing'],
    }

    TYPE_SUMMARIES = {
        'org.openvas.scan.nvt': 'OpenVAS tests run on {[[host-ipv4]]}{[[host-ipv6]]}',
        'org.openvas.scan.application-detection': 'Application detected on {[[host-ipv4]]}{[[host-ipv6]]}',
        'org.openvas.scan.os-detection': 'Operating system detected on {[[host-ipv4]]}{[[host-ipv6]]}',
        'org.openvas.scan.ssl-certificate': 'SSL certificate discovered on {[[host-ipv4]]}{[[host-ipv6]]}',
        'org.openvas.scan.open-ports': 'Open TCP/IP ports detected on {[[host-ipv4]]}{[[host-ipv6]]}',
        'org.openvas.scan.routers': 'Network router detected at {[[router-ipv4]]}{[[router-ipv6]]}',
    }

    TYPE_STORIES = {
        'org.openvas.scan.nvt':
            'OpenVAS scan [[scan-id]] performed the following tests on '
            'host [[host-ipv4]][[host-ipv6]]: [[nvt-oid]].',
        'org.openvas.scan.application-detection':
            'OpenVAS scan [[scan-id]] detected application [[application]] running on '
            'host [[host-ipv4]][[host-ipv6]]{ port [[port]]}.',
        'org.openvas.scan.os-detection':
            'OpenVAS scan [[scan-id]] detected operating system [[os]] running on '
            'host [[host-ipv4]][[host-ipv6]].',
        'org.openvas.scan.ssl-certificate':
            'OpenVAS scan [[scan-id]] discovered an SSL certificate on host [[host-ipv4]][[host-ipv6]].',
        'org.openvas.scan.open-ports':
            'OpenVAS scan [[scan-id]] detected the following open TCP/IP ports on '
            'host [[host-ipv4]][[host-ipv6]]: [[port]].',
        'org.openvas.scan.routers':
            'OpenVAS scan [[scan-id]] was executed from the scanner at [[scanner-ipv4]][[scanner-ipv6]] which detected '
            'a network router at IP [[router-ipv4]][[router-ipv6]].',
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan.nvt': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'nvt-oid': ComputingBrick.OBJECT_OID,
        },
        'org.openvas.scan.application-detection': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'port': NetworkBrick.OBJECT_HOST_PORT,
            'application': SecurityBrick.OBJECT_CPE_URI,
        },
        'org.openvas.scan.os-detection': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'os': SecurityBrick.OBJECT_CPE_URI,
        },
        'org.openvas.scan.ssl-certificate': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'host-name': NetworkBrick.OBJECT_HOST_NAME,
            'valid-from': GenericBrick.OBJECT_DATETIME,
            'valid-until': GenericBrick.OBJECT_DATETIME,
            'fingerprint': CryptoBrick.OBJECT_SSL_CERTIFICATE_FINGERPRINT_SHA1,
            'issuer-domain': NetworkBrick.OBJECT_HOST_NAME,
            'issuer-dn': CryptoBrick.OBJECT_SSL_CERTIFICATE_DN,
            'issuer-cn': CryptoBrick.OBJECT_SSL_CERTIFICATE_CN,
            'issuer-country': GeoBrick.OBJECT_COUNTRYCODE_ALPHA2,
            'issuer-province': GeoBrick.OBJECT_REGION,
            'issuer-locality': GeoBrick.OBJECT_CITY,
            'issuer-organization': GenericBrick.OBJECT_ORGANIZATION_NAME,
            'issuer-unit': GenericBrick.OBJECT_ORGANIZATION_UNIT_NAME,
            'issuer-email': EmailBrick.OBJECT_EMAIL_ADDRESS,
            'subject-domain': NetworkBrick.OBJECT_HOST_NAME_WILDCARD,
            'subject-dn': CryptoBrick.OBJECT_SSL_CERTIFICATE_DN,
            'subject-cn': CryptoBrick.OBJECT_SSL_CERTIFICATE_CN,
            'subject-country': GeoBrick.OBJECT_COUNTRYCODE_ALPHA2,
            'subject-province': GeoBrick.OBJECT_REGION,
            'subject-locality': GeoBrick.OBJECT_CITY,
            'subject-organization': GenericBrick.OBJECT_ORGANIZATION_NAME,
            'subject-unit': GenericBrick.OBJECT_ORGANIZATION_UNIT_NAME,
            'subject-email': EmailBrick.OBJECT_EMAIL_ADDRESS
        },
        'org.openvas.scan.open-ports': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'host-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'host-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'port': NetworkBrick.OBJECT_HOST_PORT
        },
        'org.openvas.scan.routers': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'scanner-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'scanner-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
            'router-ipv4': NetworkBrick.OBJECT_HOST_IPV4,
            'router-ipv6': NetworkBrick.OBJECT_HOST_IPV6,
        },
    }

    TYPE_PROPERTY_POST_PROCESSORS = {
        'org.openvas.scan.nvt': {'host-ipv4': post_process_ip, 'host-ipv6': post_process_ip},
        'org.openvas.scan.application-detection': {'host-ipv4': post_process_ip, 'host-ipv6': post_process_ip},
        'org.openvas.scan.os-detection': {'host-ipv4': post_process_ip, 'host-ipv6': post_process_ip},
        'org.openvas.scan.ssl-certificate': {'host-ipv4': post_process_ip, 'host-ipv6': post_process_ip},
        'org.openvas.scan.open-ports': {'host-ipv4': post_process_ip, 'host-ipv6': post_process_ip},
    }

    TYPE_OPTIONAL_PROPERTIES = {
        'org.openvas.scan.nvt': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.application-detection': ['host-ipv4', 'host-ipv6', 'port'],
        'org.openvas.scan.os-detection': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.ssl-certificate': True,
        'org.openvas.scan.open-ports': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.routers': True
    }

    TYPE_MANDATORY_PROPERTIES = {
        'org.openvas.scan.ssl-certificate': [
            'scan-id', 'valid-from', 'valid-until', 'fingerprint', 'issuer-dn', 'subject-dn'
        ],
        'org.openvas.scan.routers': ['scan-id']
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan.nvt': {
            'scan-id': 'scan UUID',
            'host-ipv4': 'target host (IPv4)',
            'host-ipv6': 'target host (IPv6)',
            'nvt-oid': 'OpenVAS plugin',
        },
        'org.openvas.scan.application-detection': {
            'scan-id': 'scan UUID',
            'host-ipv4': 'target host (IPv4)',
            'host-ipv6': 'target host (IPv6)',
            'port': 'port',
            'application': 'detected application',
        },
        'org.openvas.scan.os-detection': {
            'scan-id': 'scan UUID',
            'os': 'operating system',
            'host-ipv4': 'target host (IPv4)',
            'host-ipv6': 'target host (IPv6)',
        },
        'org.openvas.scan.ssl-certificate': {
            'scan-id': 'scan UUID',
            'host-ipv4': 'host (IPv4)',
            'host-ipv6': 'host (IPv6)',
            'valid-from': 'start of the validity period',
            'valid-until': 'end of the validity period',
            'issuer-cn': 'common name of the issuer',
            'issuer-dn': 'distinguished name of the issuer',
            'subject-cn': 'common name of the subject',
            'subject-dn': 'distinguished name of the subject',
        },
        'org.openvas.scan.open-ports': {
            'scan-id': 'scan UUID',
            'host-ipv4': 'target host (IPv4)',
            'host-ipv6': 'target host (IPv6)',
            'port': 'port',
        },
        'org.openvas.scan.routers': {
            'scan-id': 'scan UUID',
            'scanner-ipv4': 'scanner (IPv4)',
            'scanner-ipv6': 'scanner (IPv6)',
            'router-ipv4': 'router (IPv4)',
            'router-ipv6': 'router (IPv6)',
        },
    }

    TYPE_HASHED_PROPERTIES = {
        'org.openvas.scan.nvt':                   ['scan-id', 'host-ipv4', 'host-ipv6'],
        'org.openvas.scan.application-detection': ['scan-id', 'host-ipv4', 'host-ipv6', 'application'],
        'org.openvas.scan.os-detection':          ['scan-id', 'host-ipv4', 'host-ipv6'],
        'org.openvas.scan.ssl-certificate':       ['scan-id', 'host-ipv4', 'host-ipv6', 'fingerprint'],
        'org.openvas.scan.open-ports':            ['scan-id', 'host-ipv4', 'host-ipv6'],
        'org.openvas.scan.routers':               ['scan-id'],
    }

    TYPE_PROPERTY_MERGE_STRATEGIES = {
        'org.openvas.scan.nvt': {
            'nvt-oid': EventProperty.MERGE_ADD
        },
        'org.openvas.scan.application-detection': {
            'port': EventProperty.MERGE_ADD,
        },
        'org.openvas.scan.os-detection': {
            'os': EventProperty.MERGE_ADD
        },
        'org.openvas.scan.routers': {
            'router-ipv4': EventProperty.MERGE_ADD,
            'router-ipv6': EventProperty.MERGE_ADD,
        },
    }

    TYPE_MULTI_VALUED_PROPERTIES = {
        'org.openvas.scan.nvt': ['nvt-oid'],
        'org.openvas.scan.routers': ['router-ipv4', 'router-ipv6'],
        'org.openvas.scan.application-detection': ['port', 'application'],
        'org.openvas.scan.ssl-certificate': ['host-name', 'subject-domain'],
        'org.openvas.scan.open-ports': ['port']
    }

    TYPE_AUTO_REPAIR_NORMALIZE = {
        'org.openvas.scan.nvt': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.routers': ['scanner-ipv4', 'scanner-ipv6', 'router-ipv4', 'router-ipv6'],
        'org.openvas.scan.application-detection': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.os-detection': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.ssl-certificate': [
            'host-ipv4', 'host-ipv6', 'valid-from', 'valid-until', 'issuer-country', 'subject-country',
            'host-name', 'issuer-domain', 'subject-domain'
        ],
        'org.openvas.scan.open-ports': ['host-ipv4', 'host-ipv6'],
    }

    TYPE_AUTO_REPAIR_DROP = {
        'org.openvas.scan.nvt': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.routers': ['scanner-ipv4', 'scanner-ipv6', 'router-ipv4', 'router-ipv6'],
        'org.openvas.scan.application-detection': ['port', 'host-ipv4', 'host-ipv6'],
        'org.openvas.scan.os-detection': ['host-ipv4', 'host-ipv6'],
        'org.openvas.scan.ssl-certificate': [
            'host-ipv4', 'host-ipv6', 'issuer-domain', 'subject-domain', 'subject-country', 'issuer-country'
        ],
        'org.openvas.scan.open-ports': ['host-ipv4', 'host-ipv6'],
    }

    PARENTS_CHILDREN = [
        ['org.openvas.scan', 'executed', 'org.openvas.scan.nvt'],
        ['org.openvas.scan', 'which found', 'org.openvas.scan.application-detection'],
        ['org.openvas.scan', 'which found', 'org.openvas.scan.os-detection'],
        ['org.openvas.scan', 'which found', 'org.openvas.scan.ssl-certificate'],
        ['org.openvas.scan', 'which found', 'org.openvas.scan.open-ports'],
        ['org.openvas.scan', 'which found', 'org.openvas.scan.routers']
    ]

    CHILDREN_SIBLINGS = [
        ['org.openvas.scan.nvt', 'executed by', 'org.openvas.scan'],
        ['org.openvas.scan.application-detection', 'found by', 'org.openvas.scan'],
        ['org.openvas.scan.os-detection', 'found by', 'org.openvas.scan'],
        ['org.openvas.scan.ssl-certificate', 'found by', 'org.openvas.scan'],
        ['org.openvas.scan.open-ports', 'found by', 'org.openvas.scan'],
        ['org.openvas.scan.routers', 'found by', 'org.openvas.scan'],
    ]

    PARENT_MAPPINGS = {
        'org.openvas.scan.nvt': {
            'scan-id': 'id'
        },
        'org.openvas.scan.application-detection': {
            'scan-id': 'id'
        },
        'org.openvas.scan.os-detection': {
            'scan-id': 'id'
        },
        'org.openvas.scan.ssl-certificate': {
            'scan-id': 'id'
        },
        'org.openvas.scan.open-ports': {
            'scan-id': 'id'
        },
        'org.openvas.scan.routers': {
            'scan-id': 'id'
        },
    }

    TYPE_ATTACHMENTS = {
        'org.openvas.scan.ssl-certificate': ['certificate']
    }

    TYPE_ATTACHMENT_DISPLAY_NAMES = {
        'org.openvas.scan.ssl-certificate': {'certificate': ['DER encoded X.509 certificate']}
    }

    TYPE_ATTACHMENT_ENCODINGS = {
        'org.openvas.scan.ssl-certificate': {'certificate': 'base64'}
    }

    TYPE_ATTACHMENT_MEDIA_TYPES = {
        'org.openvas.scan.ssl-certificate': {'certificate': 'application/pkix-cert'}
    }

    TYPE_TIMESPANS = {
        'org.openvas.scan.ssl-certificate': ['valid-from', 'valid-until']
    }

    TYPE_PROPERTY_CONCEPTS = {
        'org.openvas.scan.nvt': {
            'host-ipv4': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'host-ipv6': {ComputingBrick.CONCEPT_COMPUTER: 7}
        },
        'org.openvas.scan.application-detection': {
            'host-ipv4': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'host-ipv6': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'port': {ComputingBrick.CONCEPT_COMPUTER: 0}
        },
        'org.openvas.scan.os-detection': {
            'host-ipv4': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'host-ipv6': {ComputingBrick.CONCEPT_COMPUTER: 7}
        },
        'org.openvas.scan.ssl-certificate': {
            'host-ipv4': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'host-ipv6': {ComputingBrick.CONCEPT_COMPUTER: 7}
        },
        'org.openvas.scan.open-ports': {
            'host-ipv4': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'host-ipv6': {ComputingBrick.CONCEPT_COMPUTER: 7},
            'port': {ComputingBrick.CONCEPT_COMPUTER: 0}
        },
        'org.openvas.scan.routers':
            {
                'scanner-ipv4': {SecurityBrick.CONCEPT_VULN_SCANNER: 7},
                'scanner-ipv6': {SecurityBrick.CONCEPT_VULN_SCANNER: 7},
                'router-ipv4': {NetworkBrick.CONCEPT_NETWORK_ROUTER: 7},
                'router-ipv6': {NetworkBrick.CONCEPT_NETWORK_ROUTER: 7}
            },
    }

    # Mapping of certificate name components to partial property names
    DN_FIELD_PROPERTY_MAP = {
        NameOID.COMMON_NAME: 'cn',
        NameOID.COUNTRY_NAME: 'country',
        NameOID.STATE_OR_PROVINCE_NAME: 'province',
        NameOID.LOCALITY_NAME: 'locality',
        NameOID.ORGANIZATION_NAME: 'organization',
        NameOID.ORGANIZATIONAL_UNIT_NAME: 'unit',
        NameOID.EMAIL_ADDRESS: 'email'
    }

    def post_process(self, event, input_element):

        if event.get_type_name() == 'org.openvas.scan.routers':
            yield from self.post_process_traceroute(event)
            return

        if event.get_type_name() == 'org.openvas.scan.application-detection' and 'application' not in event:
            # No application detections found for this host.
            return

        if event.get_type_name() == 'org.openvas.scan.os-detection' and 'os' not in event:
            # No OS detections found for this host.
            return

        if event.get_type_name() == 'org.openvas.scan.open-ports':
            event['port'] = [port + '/TCP' for port in event.get_any('port').split(',')]

        if event.get_type_name() == 'org.openvas.scan.ssl-certificate':
            if 'certificates' in event:
                certificate = list(event['certificates'])[0]
                if not certificate.startswith('x509:'):
                    # Not a X.509 certificate
                    return
                # Certificate value has 'x509:' prepended. Strip it.
                certificate = certificate[5:]
                del event['certificates']
                try:
                    self.process_certificate(certificate, event)
                except ValueError as e:
                    log.warning('Failed to process SSL certificate: ' + str(e))
                    return

        yield event

    def post_process_traceroute(self, event):
        hosts = event.get_any('host')
        if hosts is None:
            return

        # The hosts string is a comma separated list of the
        # IP addresses along the route from the OpenVAS scanner
        # to the scan target.
        hosts = hosts.split(',')
        if len(hosts) == 0:
            return

        # The first host in the list is the OpenVAS scanner itself.
        scanner = hosts.pop(0)

        # We assign the host IP address to both the IPv4 and IPv6
        # property. Either one of these will be invalid and will
        # be automatically removed by the EDXML transcoder mediator,
        # provided that it is configured to do so.
        parsed = IP(scanner)
        event['scanner-ipv4'] = parsed
        event['scanner-ipv6'] = parsed

        if len(hosts) > 1:
            # The original hosts list had at least three hosts
            # in it, which means it contains network routers.
            # Pop off the last host in the list, which is the
            # scanned host. Now, only routers remain.
            hosts.pop()
            for host in hosts:
                parsed = IP(host)
                event['router-ipv4'].add(parsed)
                event['router-ipv6'].add(parsed)

        del event['host']

        yield event

    def process_certificate(self, certificate, event):

        # The SSL certificates stored in OpenVAS reports are DER encoded, then base64 encoded.
        cert = x509.load_der_x509_certificate(base64.decodebytes(certificate.encode('utf-8')), default_backend())

        event.set_attachments({'certificate': certificate.strip()})

        event['valid-from'] = cert.not_valid_before
        event['valid-until'] = cert.not_valid_after
        event['fingerprint'] = codecs.encode(cert.fingerprint(hashes.SHA1()), 'hex').decode('utf-8')
        event['issuer-dn'] = cert.issuer.rfc4514_string()
        event['subject-dn'] = cert.subject.rfc4514_string()

        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            # DNS names found in this extension might contain names that are NOT among the subject
            # CN names, providing additional hosts names. We add them to the subject domain.
            event['subject-domain'].update(ext.value.get_values_for_type(x509.DNSName))
        except ExtensionNotFound:
            pass

        for field, property_name in self.DN_FIELD_PROPERTY_MAP.items():
            event['issuer-' + property_name] = {v.value for v in cert.issuer.get_attributes_for_oid(field)}

        for field, property_name in self.DN_FIELD_PROPERTY_MAP.items():
            event['subject-' + property_name] = {v.value for v in cert.subject.get_attributes_for_oid(field)}

        event['issuer-domain'].add(
            '.'.join(reversed(
                [attrib.value for attrib in cert.issuer.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)])
            ))

        event['subject-domain'].add(
            '.'.join(reversed(
                [attrib.value for attrib in cert.subject.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)])
            ))

        for domain in event['subject-domain']:
            if domain != '' and '*' not in domain:
                # Subject domain is not a wildcard
                event['host-name'].add(domain)

    @classmethod
    def create_event_type(cls, event_type_name, ontology):

        event_type = super(OpenVasHostTranscoder, cls).create_event_type(event_type_name, ontology)

        if event_type_name == 'org.openvas.scan.routers':
            # The IP address of the scanner is an identifier of a vulnerability scanner.
            event_type['scanner-ipv4'].identifies(SecurityBrick.CONCEPT_VULN_SCANNER, confidence=7)
            event_type['scanner-ipv6'].identifies(SecurityBrick.CONCEPT_VULN_SCANNER, confidence=7)
            # The IP addresses of the routers are identifiers of network routers.
            event_type['router-ipv4'].identifies(NetworkBrick.CONCEPT_NETWORK_ROUTER, confidence=7)
            event_type['router-ipv6'].identifies(NetworkBrick.CONCEPT_NETWORK_ROUTER, confidence=7)
        else:
            # The IP address of the scanned host is an identifier of a computer.
            event_type['host-ipv4'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=7)
            event_type['host-ipv6'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=7)

        if 'port' in event_type:
            # An open port of the host is a weak identifier of a computer.
            event_type['port'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=0)
            if 'host-ipv4' in event_type:
                # Create intra-concept relation between the host IP and its open ports.
                event_type['host-ipv4'].relate_intra('exposes', 'port') \
                    .because('OpenVAS detected that host [[host-ipv4]] exposes network port [[port]]')
            if 'host-ipv6' in event_type:
                # Create intra-concept relation between the host IP and its open ports.
                event_type['host-ipv6'].relate_intra('exposes', 'port') \
                    .because('OpenVAS detected that host [[host-ipv6]] exposes network port [[port]]')

        if event_type_name == 'org.openvas.scan.nvt':
            # Associate OpenVAS plugins with the vulnerability concept. This models
            # the fact that OpenVAS plugin IODs are unique identifiers of a particular
            # issue.
            event_type['nvt-oid'].identifies(OpenVASBrick.CONCEPT_VULNERABILITY, confidence=10)

        if event_type_name == 'org.openvas.scan.application-detection':
            # A detected application is an identifier of a computer, but it is a are weak identifier.
            event_type['application'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=0)
            # Create intra-concept relations between the host IP and any detected applications.
            event_type['host-ipv4'].relate_intra('runs', 'application') \
                .because('OpenVAS detected [[application]] running on host [[host-ipv4]]')
            event_type['host-ipv6'].relate_intra('runs', 'application') \
                .because('OpenVAS detected [[application]] running on host [[host-ipv6]]')

        if event_type_name == 'org.openvas.scan.os-detection':
            # The detected operating system is an identifier of a computer, but it is a are weak identifier.
            event_type['os'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=0)
            # Create intra-concept relations between the host IP and any detected OSes.
            event_type['host-ipv4'].relate_intra('runs', 'os') \
                .because('OpenVAS found evidence that host [[host-ipv4]] runs on [[os]]')
            event_type['host-ipv6'].relate_intra('runs', 'os') \
                .because('OpenVAS found evidence that host [[host-ipv6]] runs on [[os]]')

        if event_type_name == 'org.openvas.scan.ssl-certificate':
            event_type['issuer-organization'].identifies(GenericBrick.CONCEPT_ORGANIZATION, confidence=9)
            event_type['subject-organization'].identifies(GenericBrick.CONCEPT_ORGANIZATION, confidence=9)
            event_type['subject-organization'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=0)
            event_type['issuer-country'].identifies(GenericBrick.CONCEPT_ORGANIZATION, confidence=0)
            event_type['issuer-email'].identifies(GenericBrick.CONCEPT_ORGANIZATION, confidence=9)
            event_type['subject-email'].identifies(GenericBrick.CONCEPT_ORGANIZATION, confidence=9)
            event_type['subject-email'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=0)
            event_type['host-name'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=9)
            event_type['fingerprint'].identifies(ComputingBrick.CONCEPT_COMPUTER, confidence=1)

            event_type['fingerprint'].relate_intra('protects', 'host-ipv4')\
                .because('OpenVAS found an SSL certificate on host [[host-ipv4]] having finger print [[fingerprint]]')
            event_type['fingerprint'].relate_intra('protects', 'host-ipv6')\
                .because('OpenVAS found an SSL certificate on host [[host-ipv6]] having finger print [[fingerprint]]')

            # Relate the subject organization to the computer as owner.
            event_type['host-name'].relate_intra('is associated with', 'host-ipv4')\
                .because('OpenVAS found an SSL certificate on host [[host-ipv4]] containing [[host-name]] as subject')
            event_type['host-name'].relate_intra('is associated with', 'host-ipv6')\
                .because('OpenVAS found an SSL certificate on host [[host-ipv6]] containing [[host-name]] as subject')

            # Relate the subject organization to the computer as owner.
            event_type['subject-organization'].relate_inter(
                'owns', 'host-ipv4', source_concept_name=GenericBrick.CONCEPT_ORGANIZATION)\
                .because('OpenVAS found an SSL certificate on host [[host-ipv4]] issued for [[subject-organization]]')
            event_type['subject-organization'].relate_inter(
                'owns', 'host-ipv6', source_concept_name=GenericBrick.CONCEPT_ORGANIZATION)\
                .because('OpenVAS found an SSL certificate on host [[host-ipv6]] issued for [[subject-organization]]')

            # Relate the subject organization as an attribute of the computer.
            event_type['subject-organization'].relate_intra(
                'owns', 'host-ipv4', source_concept_name=ComputingBrick.CONCEPT_COMPUTER)\
                .because('OpenVAS found an SSL certificate on host [[host-ipv4]] issued for [[subject-organization]]')
            event_type['subject-organization'].relate_intra(
                'owns', 'host-ipv6', source_concept_name=ComputingBrick.CONCEPT_COMPUTER)\
                .because('OpenVAS found an SSL certificate on host [[host-ipv6]] issued for [[subject-organization]]')

            # The subject email is probably the administrative contact for the computer.
            event_type['subject-email'].relate_intra(
                'is administering', 'host-ipv4', source_concept_name=ComputingBrick.CONCEPT_COMPUTER)\
                .because('OpenVAS found an SSL certificate on host [[host-ipv4]] issued for [[subject-email]]')
            event_type['subject-email'].relate_intra(
                'is administering', 'host-ipv6', source_concept_name=ComputingBrick.CONCEPT_COMPUTER)\
                .because('OpenVAS found an SSL certificate on host [[host-ipv6]] issued for [[subject-email]]')

            # The issuer is responsible for protecting SSL traffic of the computer.
            event_type['issuer-organization'].relate_inter('protects', 'host-ipv4')\
                .because('OpenVAS found an SSL certificate on host [[host-ipv4]] issued by [[issuer-organization]]')
            event_type['issuer-organization'].relate_inter('protects', 'host-ipv6')\
                .because('OpenVAS found an SSL certificate on host [[host-ipv6]] issued by [[issuer-organization]]')

            event_type['issuer-email'].relate_intra('is used by', 'issuer-organization')\
                .because('OpenVAS found an SSL certificate linking [[issuer-organization]] to [[issuer-email]]')

            event_type['issuer-organization'].relate_intra('is located in', 'issuer-country')\
                .because('OpenVAS found an SSL certificate issed by [[issuer-organization]] in [[issuer-country]]')

        return event_type
