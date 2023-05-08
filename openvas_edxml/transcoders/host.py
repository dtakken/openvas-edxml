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
from edxml_bricks.computing.networking.generic import NetworkingBrick
from openvas_edxml.logger import log
from openvas_edxml.transcoders import post_process_ip


class OpenVasHostTranscoder(XmlTranscoder):

    TYPES = [
        'org.openvas.scan.nvt',
        'org.openvas.scan.application-detection',
        'org.openvas.scan.os-detection',
        'org.openvas.scan.ssl-certificate',
        'org.openvas.scan.open-ports',
        'org.openvas.scan.routers'
    ]

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
            'ip': ['host.ipv4', 'host.ipv6'],
            'detail/name[text() = "EXIT_CODE"]/../source/name': 'nvt.oid',
            '../scan_start': 'time'
        },
        'org.openvas.scan.application-detection': {
            '../../@id': 'scan-id',
            '../ip': ['host.ipv4', 'host.ipv6'],
            'name': 'application',
            'value': 'port',
            '../../scan_start': 'time'
        },
        'org.openvas.scan.os-detection': {
            '../../@id': 'scan-id',
            '../ip': ['host.ipv4', 'host.ipv6'],
            'name': 'os',
            '../../scan_start': 'time'
        },
        'org.openvas.scan.ssl-certificate': {
            '../../@id': 'scan-id',
            'ip|../ip': ['host.ipv4', 'host.ipv6'],
            'value': 'certificates',
            '../../scan_start': 'time'
        },
        'org.openvas.scan.open-ports': {
            '../../@id': 'scan-id',
            'ip|../ip': ['host.ipv4', 'host.ipv6'],
            'detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.900239"]/../../value': 'port',
            '../scan_start': 'time'
        },
        'org.openvas.scan.routers': {
            '../../@id': 'scan-id',
            'value': 'host',
            '../../scan_start': 'time'
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
        'org.openvas.scan.nvt': 'OpenVAS tests run on [[merge:host.ipv4,host.ipv6]]',
        'org.openvas.scan.application-detection': 'Application detected on [[merge:host.ipv4,host.ipv6]]',
        'org.openvas.scan.os-detection': 'Operating system detected on [[merge:host.ipv4,host.ipv6]]',
        'org.openvas.scan.ssl-certificate': 'SSL certificate discovered on [[merge:host.ipv4,host.ipv6]]',
        'org.openvas.scan.open-ports': 'Open TCP/IP ports detected on [[merge:host.ipv4,host.ipv6]]',
        'org.openvas.scan.routers': 'Network router detected at {[[merge:router.ipv4,router.ipv6]]}',
    }

    TYPE_STORIES = {
        'org.openvas.scan.nvt':
            'OpenVAS scan [[scan-id]], which started on [[date_time:time,minute]], performed the following tests on '
            'host [[merge:host.ipv4,host.ipv6]]: [[nvt.oid]].',
        'org.openvas.scan.application-detection':
            'OpenVAS scan [[scan-id]], which started on [[date_time:time,minute]], detected application '
            '[[application]] running on host [[merge:host.ipv4,host.ipv6]]{ port [[port]]}.',
        'org.openvas.scan.os-detection':
            'OpenVAS scan [[scan-id]], which started on [[date_time:time,minute]], detected operating system [[os]] '
            'running on host [[merge:host.ipv4,host.ipv6]].',
        'org.openvas.scan.ssl-certificate':
            'OpenVAS scan [[scan-id]], which started on [[date_time:time,minute]], discovered an SSL certificate on '
            'host [[merge:host.ipv4,host.ipv6]]. The certificate, which has fingerprint [[cert.fingerprint]], '
            'was issued{ by [[cert.issuer.dn]]} for the host(s) identified by subject string [[cert.subject.dn]] '
            'and is valid from [[date_time:cert.valid.from,date]] until [[date_time:cert.valid.until,date]].'
            '{ The following details about the subject(s) are contained in the certificate:{'
            '{ The domain name(s): [[cert.subject.domain]].}'
            '{ Wildcard domain names: [[cert.subject.domain-wildcard]].}'
            '{ The subject is supposedly located in '
            '[[merge:cert.subject.locality,cert.subject.province,cert.subject.country]].}'
            '{ The certificate was issued for [[merge:cert.subject.organization,cert.subject.unit]].}'
            '{ A contact e-mail address was specified: [[cert.subject.email]]}}.}'
            '{ The following details about the issuer are contained in the '
            '[[unless_empty:cert.issuer.dn,certificate]]: {'
            '{ The domain name: [[cert.issuer.domain]].}'
            '{ The issuer is supposedly located in '
            '[[merge:cert.issuer.locality,cert.issuer.province,cert.issuer.country]].}'
            '{ The certificate was issued by [[merge:cert.issuer.organization,cert.issuer.unit]].}'
            '{ A contact e-mail address was specified: [[cert.issuer.email]]}}.}',
        'org.openvas.scan.open-ports':
            'OpenVAS scan [[scan-id]], which started on [[date_time:time,minute]], detected the following open '
            'TCP/IP ports on host [[merge:host.ipv4,host.ipv6]]: [[port]].',
        'org.openvas.scan.routers':
            'OpenVAS scan [[scan-id]], which started on [[date_time:time,minute]], was executed from the scanner at '
            '[[merge:scanner.ipv4,scanner.ipv6]] which detected a network router at IP '
            '[[merge:router.ipv4,router.ipv6]].',
    }

    TYPE_PROPERTIES = {
        'org.openvas.scan.nvt': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'nvt.oid': ComputingBrick.OBJECT_OID,
        },
        'org.openvas.scan.application-detection': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'port': NetworkingBrick.OBJECT_HOST_PORT,
            'application': ComputingBrick.OBJECT_CPE_URI,
        },
        'org.openvas.scan.os-detection': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'os': ComputingBrick.OBJECT_CPE_URI,
        },
        'org.openvas.scan.ssl-certificate': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'cert.valid.from': GenericBrick.OBJECT_DATETIME,
            'cert.valid.until': GenericBrick.OBJECT_DATETIME,
            'cert.fingerprint': CryptoBrick.OBJECT_CERTIFICATE_FINGERPRINT_SHA1,
            'cert.issuer.domain': NetworkingBrick.OBJECT_HOST_NAME,
            'cert.issuer.dn': CryptoBrick.OBJECT_CERTIFICATE_DN,
            'cert.issuer.cn': CryptoBrick.OBJECT_CERTIFICATE_CN,
            'cert.issuer.country': GeoBrick.OBJECT_COUNTRYCODE_ALPHA2,
            'cert.issuer.province': GeoBrick.OBJECT_REGION,
            'cert.issuer.locality': GeoBrick.OBJECT_CITY,
            'cert.issuer.organization': GenericBrick.OBJECT_ORGANIZATION_NAME,
            'cert.issuer.unit': GenericBrick.OBJECT_ORGANIZATION_UNIT_NAME,
            'cert.issuer.email': EmailBrick.OBJECT_EMAIL_ADDRESS,
            'cert.subject.domain': NetworkingBrick.OBJECT_HOST_NAME,
            'cert.subject.domain-wildcard': NetworkingBrick.OBJECT_HOST_NAME_WILDCARD,
            'cert.subject.dn': CryptoBrick.OBJECT_CERTIFICATE_DN,
            'cert.subject.cn': CryptoBrick.OBJECT_CERTIFICATE_CN,
            'cert.subject.country': GeoBrick.OBJECT_COUNTRYCODE_ALPHA2,
            'cert.subject.province': GeoBrick.OBJECT_REGION,
            'cert.subject.locality': GeoBrick.OBJECT_CITY,
            'cert.subject.organization': GenericBrick.OBJECT_ORGANIZATION_NAME,
            'cert.subject.unit': GenericBrick.OBJECT_ORGANIZATION_UNIT_NAME,
            'cert.subject.email': EmailBrick.OBJECT_EMAIL_ADDRESS
        },
        'org.openvas.scan.open-ports': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'host.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'host.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'port': NetworkingBrick.OBJECT_HOST_PORT,
        },
        'org.openvas.scan.routers': {
            'scan-id': ComputingBrick.OBJECT_UUID,
            'time': GenericBrick.OBJECT_DATETIME,
            'scanner.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'scanner.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
            'router.ipv4': NetworkingBrick.OBJECT_HOST_IPV4,
            'router.ipv6': NetworkingBrick.OBJECT_HOST_IPV6,
        },
    }

    TYPE_UNIVERSALS_NAMES = {
        'org.openvas.scan.ssl-certificate': {
            'cert.issuer.dn': 'cert.issuer.organization',
        },
    }

    TYPE_UNIVERSALS_CONTAINERS = {
        'org.openvas.scan.ssl-certificate': {
            'cert.issuer.unit': 'cert.issuer.organization',
            'cert.subject.unit': 'cert.subject.organization',
            'cert.issuer.province': 'cert.issuer.country',
            'cert.issuer.locality': 'cert.issuer.province',
            'cert.subject.province': 'cert.subject.country',
            'cert.subject.locality': 'cert.subject.province',
        },
    }

    TYPE_PROPERTY_POST_PROCESSORS = {
        'org.openvas.scan.nvt': {'host.ipv4': post_process_ip, 'host.ipv6': post_process_ip},
        'org.openvas.scan.application-detection': {'host.ipv4': post_process_ip, 'host.ipv6': post_process_ip},
        'org.openvas.scan.os-detection': {'host.ipv4': post_process_ip, 'host.ipv6': post_process_ip},
        'org.openvas.scan.ssl-certificate': {'host.ipv4': post_process_ip, 'host.ipv6': post_process_ip},
        'org.openvas.scan.open-ports': {'host.ipv4': post_process_ip, 'host.ipv6': post_process_ip},
    }

    TYPE_OPTIONAL_PROPERTIES = {
        'org.openvas.scan.nvt': ['host.ipv4', 'host.ipv6'],
        'org.openvas.scan.application-detection': ['host.ipv4', 'host.ipv6', 'port'],
        'org.openvas.scan.os-detection': ['host.ipv4', 'host.ipv6'],
        'org.openvas.scan.ssl-certificate': True,
        'org.openvas.scan.open-ports': ['host.ipv4', 'host.ipv6'],
        'org.openvas.scan.routers': True
    }

    TYPE_MANDATORY_PROPERTIES = {
        'org.openvas.scan.ssl-certificate': [
            'scan-id', 'cert.valid.from', 'cert.valid.until', 'cert.fingerprint', 'cert.subject.dn'
        ],
        'org.openvas.scan.routers': ['scan-id']
    }

    TYPE_PROPERTY_DESCRIPTIONS = {
        'org.openvas.scan.nvt': {
            'scan-id': 'scan UUID',
            'host.ipv4': 'target host (IPv4)',
            'host.ipv6': 'target host (IPv6)',
            'nvt.oid': 'OpenVAS plugin',
        },
        'org.openvas.scan.application-detection': {
            'scan-id': 'scan UUID',
            'host.ipv4': 'target host (IPv4)',
            'host.ipv6': 'target host (IPv6)',
            'port': 'port',
            'application': 'detected application',
        },
        'org.openvas.scan.os-detection': {
            'scan-id': 'scan UUID',
            'os': 'operating system',
            'host.ipv4': 'target host (IPv4)',
            'host.ipv6': 'target host (IPv6)',
        },
        'org.openvas.scan.ssl-certificate': {
            'scan-id': 'scan UUID',
            'host.ipv4': 'host (IPv4)',
            'host.ipv6': 'host (IPv6)',
            'cert.valid.from': 'start of the validity period',
            'cert.valid.until': 'end of the validity period',
            'cert.issuer.cn': 'common name of the issuer',
            'cert.issuer.dn': 'distinguished name of the issuer',
            'cert.subject.cn': 'common name of the subject',
            'cert.subject.dn': 'distinguished name of the subject',
        },
        'org.openvas.scan.open-ports': {
            'scan-id': 'scan UUID',
            'host.ipv4': 'target host (IPv4)',
            'host.ipv6': 'target host (IPv6)',
            'port': 'port',
        },
        'org.openvas.scan.routers': {
            'scan-id': 'scan UUID',
            'scanner.ipv4': 'scanner (IPv4)',
            'scanner.ipv6': 'scanner (IPv6)',
            'router.ipv4': 'router (IPv4)',
            'router.ipv6': 'router (IPv6)',
        },
    }

    TYPE_HASHED_PROPERTIES = {
        'org.openvas.scan.nvt':                   ['scan-id', 'host.ipv4', 'host.ipv6'],
        'org.openvas.scan.application-detection': ['scan-id', 'host.ipv4', 'host.ipv6', 'application'],
        'org.openvas.scan.os-detection':          ['scan-id', 'host.ipv4', 'host.ipv6'],
        'org.openvas.scan.ssl-certificate':       ['scan-id', 'host.ipv4', 'host.ipv6', 'cert.fingerprint'],
        'org.openvas.scan.open-ports':            ['scan-id', 'host.ipv4', 'host.ipv6'],
        'org.openvas.scan.routers':               ['scan-id'],
    }

    TYPE_PROPERTY_MERGE_STRATEGIES = {
        'org.openvas.scan.nvt': {
            'nvt.oid': EventProperty.MERGE_ADD
        },
        'org.openvas.scan.application-detection': {
            'port': EventProperty.MERGE_ADD,
        },
        'org.openvas.scan.os-detection': {
            'os': EventProperty.MERGE_ADD
        },
        'org.openvas.scan.routers': {
            'router.ipv4': EventProperty.MERGE_ADD,
            'router.ipv6': EventProperty.MERGE_ADD,
        },
    }

    TYPE_MULTI_VALUED_PROPERTIES = {
        'org.openvas.scan.nvt': ['nvt.oid'],
        'org.openvas.scan.routers': ['router.ipv4', 'router.ipv6'],
        'org.openvas.scan.application-detection': ['port', 'application'],
        'org.openvas.scan.os-detection': ['os'],
        'org.openvas.scan.ssl-certificate': [
            'cert.subject.domain', 'cert.subject.domain-wildcard', 'cert.issuer.cn',
            'cert.subject.cn', 'cert.subject.unit'
        ],
        'org.openvas.scan.open-ports': ['port']
    }

    TYPE_AUTO_REPAIR_NORMALIZE = {
        'org.openvas.scan.nvt': ['host.ipv4', 'host.ipv6', 'time'],
        'org.openvas.scan.routers': ['scanner.ipv4', 'scanner.ipv6', 'router.ipv4', 'router.ipv6', 'time'],
        'org.openvas.scan.application-detection': ['host.ipv4', 'host.ipv6', 'time'],
        'org.openvas.scan.os-detection': ['host.ipv4', 'host.ipv6', 'time'],
        'org.openvas.scan.ssl-certificate': [
            'host.ipv4', 'host.ipv6',
            'cert.valid.from', 'cert.valid.until',
            'cert.issuer.country', 'cert.subject.country',
            'cert.issuer.domain', 'cert.subject.domain',
            'time'
        ],
        'org.openvas.scan.open-ports': ['host.ipv4', 'host.ipv6', 'time'],
    }

    TYPE_AUTO_REPAIR_DROP = {
        'org.openvas.scan.nvt': ['host.ipv4', 'host.ipv6'],
        'org.openvas.scan.routers': ['scanner.ipv4', 'scanner.ipv6', 'router.ipv4', 'router.ipv6'],
        'org.openvas.scan.application-detection': ['port', 'host.ipv4', 'host.ipv6'],
        'org.openvas.scan.os-detection': ['host.ipv4', 'host.ipv6'],
        'org.openvas.scan.ssl-certificate': [
            'host.ipv4', 'host.ipv6',
            'cert.issuer.domain', 'cert.subject.domain',
            'cert.subject.country', 'cert.issuer.country'
        ],
        'org.openvas.scan.open-ports': ['host.ipv4', 'host.ipv6'],
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

    TYPE_TIME_SPANS = {
        'org.openvas.scan.ssl-certificate': ['cert.valid.from', 'cert.valid.until']
    }

    TYPE_PROPERTY_CONCEPTS = {
        'org.openvas.scan.nvt': {
            # Associate OpenVAS plugins with the finding concept. This models
            # the fact that OpenVAS plugin IODs are unique identifiers of a particular
            # type of finding.
            'nvt.oid': {OpenVASBrick.CONCEPT_FINDING: 10},
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8}
        },
        'org.openvas.scan.application-detection': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'application': {ComputingBrick.CONCEPT_COMPUTER: 0},
            'port': {ComputingBrick.CONCEPT_COMPUTER: 0}
        },
        'org.openvas.scan.os-detection': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'os': {ComputingBrick.CONCEPT_COMPUTER: 0},
        },
        'org.openvas.scan.ssl-certificate': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8},

            'cert.valid.from': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 1},
            'cert.valid.until': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 1},
            'cert.fingerprint': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 10},

            'cert.issuer.domain': {GenericBrick.CONCEPT_ORGANIZATION: 7},
            'cert.issuer.dn': {GenericBrick.CONCEPT_ORGANIZATION: 9},
            'cert.issuer.cn': {GenericBrick.CONCEPT_ORGANIZATION: 6},
            'cert.issuer.country': {GenericBrick.CONCEPT_ORGANIZATION: 1},
            'cert.issuer.province': {GenericBrick.CONCEPT_ORGANIZATION: 1},
            'cert.issuer.locality': {GenericBrick.CONCEPT_ORGANIZATION: 1},
            'cert.issuer.organization': {GenericBrick.CONCEPT_ORGANIZATION: 9},
            'cert.issuer.unit': {GenericBrick.CONCEPT_ORGANIZATION: 2},
            'cert.issuer.email': {GenericBrick.CONCEPT_ORGANIZATION: 9},

            'cert.subject.domain': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 8, ComputingBrick.CONCEPT_COMPUTER: 8},
            'cert.subject.domain-wildcard': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 6},
            'cert.subject.dn': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 9},
            'cert.subject.cn': {CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: 6},
            'cert.subject.country': {GenericBrick.CONCEPT_ORGANIZATION: 1},
            'cert.subject.province': {GenericBrick.CONCEPT_ORGANIZATION: 1},
            'cert.subject.locality': {GenericBrick.CONCEPT_ORGANIZATION: 1},
            'cert.subject.organization': {GenericBrick.CONCEPT_ORGANIZATION: 9},
            'cert.subject.unit': {GenericBrick.CONCEPT_ORGANIZATION: 2},
            'cert.subject.email': {GenericBrick.CONCEPT_ORGANIZATION: 9},
        },
        'org.openvas.scan.open-ports': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 8},
            'port': {ComputingBrick.CONCEPT_COMPUTER: 0}
        },
        'org.openvas.scan.routers': {
            'scanner.ipv4': {SecurityBrick.CONCEPT_VULNERABILITY_SCANNER: 8},
            'scanner.ipv6': {SecurityBrick.CONCEPT_VULNERABILITY_SCANNER: 8},
            'router.ipv4': {NetworkingBrick.CONCEPT_NETWORK_ROUTER: 8},
            'router.ipv6': {NetworkingBrick.CONCEPT_NETWORK_ROUTER: 8}
        },
    }

    TYPE_PROPERTY_CONCEPTS_CNP = {
        'org.openvas.scan.nvt': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
        },
        'org.openvas.scan.application-detection': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
        },
        'org.openvas.scan.os-detection': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'os': {ComputingBrick.CONCEPT_COMPUTER: 160},
        },
        'org.openvas.scan.open-ports': {
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
        },
        'org.openvas.scan.routers': {
            'scanner.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'scanner.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'router.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'router.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
        },
        'org.openvas.scan.ssl-certificate': {
            # Computer:
            'cert.subject.domain': {ComputingBrick.CONCEPT_COMPUTER: 192},
            'host.ipv4': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'host.ipv6': {ComputingBrick.CONCEPT_COMPUTER: 180},
            'cert.fingerprint': {ComputingBrick.CONCEPT_COMPUTER: 0},
            # Organization:
            'cert.issuer.organization': {GenericBrick.CONCEPT_ORGANIZATION: 192},
            'cert.subject.organization': {GenericBrick.CONCEPT_ORGANIZATION: 192},
            'cert.issuer.cn': {GenericBrick.CONCEPT_ORGANIZATION: 180},
            'cert.subject.cn': {GenericBrick.CONCEPT_ORGANIZATION: 180},
            'cert.issuer.country': {GenericBrick.CONCEPT_ORGANIZATION: 64},
            'cert.issuer.email': {GenericBrick.CONCEPT_ORGANIZATION: 0},
            'cert.subject.email': {GenericBrick.CONCEPT_ORGANIZATION: 0},
        }
    }

    TYPE_PROPERTY_ATTRIBUTES = {
        'org.openvas.scan.nvt': {
            'nvt.oid': {
                OpenVASBrick.CONCEPT_FINDING: [
                    ComputingBrick.OBJECT_OID + ':openvas.plugin', 'OpenVAS detection plugin ID'
                ]
            }
        },
        'org.openvas.scan.ssl-certificate': {
            'cert.valid.from': {
                CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: ['datetime:cert.valid.from', '"valid from" timestamp']
            },
            'cert.valid.until': {
                CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE: ['datetime:cert.valid.until', '"valid until" timestamp']
            }
        },
        'org.openvas.scan.application-detection': {
            'port': {ComputingBrick.CONCEPT_COMPUTER: ['computing.networking.host.port:open', 'open TCP/IP port']}
        },
        'org.openvas.scan.open-ports': {
            'port': {ComputingBrick.CONCEPT_COMPUTER: ['computing.networking.host.port:open', 'open TCP/IP port']}
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
        event['scanner.ipv4'] = parsed
        event['scanner.ipv6'] = parsed

        if len(hosts) > 1:
            # The original hosts list had at least three hosts
            # in it, which means it contains network routers.
            # Pop off the last host in the list, which is the
            # scanned host. Now, only routers remain.
            hosts.pop()
            for host in hosts:
                if host == '* * *':
                    # Host did not respond.
                    continue
                parsed = IP(host)
                event['router.ipv4'].add(parsed)
                event['router.ipv6'].add(parsed)

        del event['host']

        yield event

    def process_certificate(self, certificate, event):

        # The SSL certificates stored in OpenVAS reports are DER encoded, then base64 encoded.
        cert = x509.load_der_x509_certificate(base64.decodebytes(certificate.encode('utf-8')), default_backend())

        event.attachments['certificate']['certificate'] = certificate.strip()

        event['cert.valid.from'] = cert.not_valid_before
        event['cert.valid.until'] = cert.not_valid_after
        event['cert.fingerprint'] = codecs.encode(cert.fingerprint(hashes.SHA1()), 'hex').decode('utf-8')

        # Below we sort the components of the distinguished names. We do that because the ordering
        # of the components in the RFC 4514 string varies between Python runs. We want the DN strings
        # to come out the same way each time.
        event['cert.issuer.dn'] = ','.join(sorted(cert.issuer.rfc4514_string().split(',')))
        event['cert.subject.dn'] = ','.join(sorted(cert.subject.rfc4514_string().split(',')))

        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            # DNS names found in this extension might contain names that are NOT among the subject
            # CN names, providing additional hosts names. We add them to the subject domain.
            event['cert.subject.domain'].update([name.lower() for name in ext.value.get_values_for_type(x509.DNSName)])
        except ExtensionNotFound:
            pass

        for field, property_name in self.DN_FIELD_PROPERTY_MAP.items():
            event['cert.issuer.' + property_name] = {v.value for v in cert.issuer.get_attributes_for_oid(field)}

        for field, property_name in self.DN_FIELD_PROPERTY_MAP.items():
            event['cert.subject.' + property_name] = {v.value for v in cert.subject.get_attributes_for_oid(field)}

        event['cert.issuer.domain'].add(
            '.'.join(reversed(
                [attrib.value.lower() for attrib in cert.issuer.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)])
            ))

        event['cert.subject.domain'].add(
            '.'.join(reversed(
                [attrib.value.lower() for attrib in cert.subject.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)])
            ))

        if event['cert.issuer.dn'] == event['cert.subject.dn']:
            # We have a self-signed certificate. In that case we
            # omit the cert.issuer. We do that because the issuer is
            # associated with the organization concept, we do not
            # want hosts to be mistaken for organizations.
            for property_name in event.keys():
                if property_name.startswith('cert.issuer.'):
                    del event[property_name]

        for issuer_subject in ['issuer', 'subject']:
            for domain in list(event[f"cert.{issuer_subject}.domain"]):
                if domain == '' or domain == 'localhost':
                    # Domain does not look like a useful host identifier.
                    event[f"cert.{issuer_subject}.domain"].remove(domain)
                    continue
                if '*' in domain:
                    # Wildcard domain, move to appropriate property.
                    event[f"cert.{issuer_subject}.domain"].remove(domain)
                    event[f"cert.{issuer_subject}.domain-wildcard"].add(domain)

    @classmethod
    def create_event_type(cls, event_type_name, ontology):

        event_type = super().create_event_type(event_type_name, ontology)

        if 'port' in event_type:
            if 'host.ipv4' in event_type:
                # Create intra-concept relation between the host IP and its open ports.
                event_type['host.ipv4'].relate_intra('exposes', 'port') \
                    .because('OpenVAS detected that host [[host.ipv4]] exposes network port [[port]]')
            if 'host.ipv6' in event_type:
                # Create intra-concept relation between the host IP and its open ports.
                event_type['host.ipv6'].relate_intra('exposes', 'port') \
                    .because('OpenVAS detected that host [[host.ipv6]] exposes network port [[port]]')

        if event_type_name == 'org.openvas.scan.application-detection':
            # Create intra-concept relations between the host IP and any detected applications.
            event_type['host.ipv4'].relate_intra('runs', 'application') \
                .because('OpenVAS detected [[application]] running on host [[host.ipv4]]')
            event_type['host.ipv6'].relate_intra('runs', 'application') \
                .because('OpenVAS detected [[application]] running on host [[host.ipv6]]')

        if event_type_name == 'org.openvas.scan.os-detection':
            # Create intra-concept relations between the host IP and any detected OSes.
            event_type['host.ipv4'].relate_intra('runs', 'os') \
                .because('OpenVAS found evidence that host [[host.ipv4]] runs on [[os]]')
            event_type['host.ipv6'].relate_intra('runs', 'os') \
                .because('OpenVAS found evidence that host [[host.ipv6]] runs on [[os]]')

        if event_type_name == 'org.openvas.scan.ssl-certificate':
            # Relate issuer DN to other attributes of the organization that issued the certificate
            event_type['cert.issuer.dn'].relate_intra('has', 'cert.issuer.domain')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.domain]]')
            event_type['cert.issuer.dn'].relate_intra('has', 'cert.issuer.cn')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.cn]]')
            event_type['cert.issuer.dn'].relate_intra('is located in', 'cert.issuer.country')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.country]]')
            event_type['cert.issuer.dn'].relate_intra('is located in', 'cert.issuer.province')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.province]]')
            event_type['cert.issuer.dn'].relate_intra('is located in', 'cert.issuer.locality')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.locality]]')
            event_type['cert.issuer.dn'].relate_intra('has', 'cert.issuer.organization')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.organization]]')
            event_type['cert.issuer.dn'].relate_intra('comprises', 'cert.issuer.unit')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.unit]]')
            event_type['cert.issuer.dn'].relate_intra('reachable at', 'cert.issuer.email')\
                .because('an SSL certificate issued by [[cert.issuer.dn]] contains [[cert.issuer.email]]')

            # Relate subject organization name to other attributes of the organization
            event_type['cert.subject.organization'].relate_intra('is located in', 'cert.subject.country')\
                .because('an SSL certificate issued for [[cert.subject.organization]] mentions '
                         '[[cert.subject.country]] in its subject information')
            event_type['cert.subject.organization'].relate_intra('is located in', 'cert.subject.province')\
                .because('an SSL certificate issued for [[cert.subject.organization]] mentions '
                         '[[cert.subject.province]] in its subject information')
            event_type['cert.subject.organization'].relate_intra('is located in', 'cert.subject.locality')\
                .because('an SSL certificate issued for [[cert.subject.organization]] mentions '
                         '[[cert.subject.locality]] in its subject information')
            event_type['cert.subject.organization'].relate_intra('comprises', 'cert.subject.unit')\
                .because('an SSL certificate issued for [[cert.subject.organization]] mentions '
                         '[[cert.subject.unit]] in its subject information')
            event_type['cert.subject.organization'].relate_intra('reachable at', 'cert.subject.email')\
                .because('an SSL certificate issued for [[cert.subject.organization]] mentions '
                         '[[cert.subject.email]] in its subject information')

            # Relate certificates to issuer and subject organizations
            event_type['cert.fingerprint'].relate_inter('issued by', 'cert.issuer.dn')\
                .because('OpenVAS found an SSL certificate issued by [[cert.issuer.dn]] having [[cert.fingerprint]]')
            event_type['cert.fingerprint'].relate_inter('issued for', 'cert.subject.organization')\
                .because('OpenVAS found an SSL certificate issued for [[cert.subject.organization]] '
                         'having [[cert.fingerprint]]')

            # Relate certificates to the host it is found on.
            event_type['cert.fingerprint'].relate_inter('protects', 'host.ipv4')\
                .because('OpenVAS found an SSL certificate on [[host.ipv4]] having [[cert.fingerprint]]')
            event_type['cert.fingerprint'].relate_inter('protects', 'host.ipv6')\
                .because('OpenVAS found an SSL certificate on [[host.ipv6]] having [[cert.fingerprint]]')

            # Relate certificate cert.fingerprint to other certificate attributes
            event_type['cert.fingerprint'].relate_intra('is valid from', 'cert.valid.from').because(
                'OpenVAS found an SSL certificate having [[cert.fingerprint]] which contains [[cert.valid.from]]')
            event_type['cert.fingerprint'].relate_intra('is valid until', 'cert.valid.until').because(
                'OpenVAS found an SSL certificate having [[cert.fingerprint]] which contains [[cert.valid.until]]')
            event_type['cert.fingerprint'].relate_intra(
                'protects', 'cert.subject.domain', target_concept_name=CryptoBrick.CONCEPT_PUBKEY_CERTIFICATE).because(
                'OpenVAS found an SSL certificate having [[cert.fingerprint]] '
                'which was issued for [[cert.subject.domain]]'
            )
            event_type['cert.fingerprint'].relate_intra(
                'protects', 'cert.subject.domain-wildcard').because(
                'OpenVAS found an SSL certificate having [[cert.fingerprint]] '
                'which was issued for [[cert.subject.domain-wildcard]]'
            )
            event_type['cert.fingerprint'].relate_intra('protects', 'cert.subject.dn').because(
                'OpenVAS found an SSL certificate having [[cert.fingerprint]] which is issued for [[cert.subject.dn]]')
            event_type['cert.fingerprint'].relate_intra('protects', 'cert.subject.cn').because(
                'OpenVAS found an SSL certificate having [[cert.fingerprint]] which is issued for [[cert.subject.cn]]')

            # Relate the subject host name to the IP address of the computer. Note that this relation
            # does not guarantee that the host actually has that host name. The same certificate may
            # be used on multiple machines, each having a different host name. The reduced confidence
            # reflects that.
            event_type['cert.subject.domain'].relate_intra(
                'is associated with', 'host.ipv4', confidence=7, source_concept_name=ComputingBrick.CONCEPT_COMPUTER
            ).because('OpenVAS found an SSL certificate issued for [[cert.subject.domain]] on host [[host.ipv4]]')
            event_type['cert.subject.domain'].relate_intra(
                'is associated with', 'host.ipv6', confidence=7, source_concept_name=ComputingBrick.CONCEPT_COMPUTER
            ).because('OpenVAS found an SSL certificate issued for [[cert.subject.domain]] on host [[host.ipv6]]')

        return event_type
