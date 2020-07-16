from os.path import dirname

import pytest

import edxml
from edxml.transcode.xml import XmlTranscoderTestHarness
from openvas_edxml import register_transcoders, OpenVasHostTranscoder


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(dirname(__file__) + '/fixtures', OpenVasHostTranscoder())
    register_transcoders(harness)
    harness.add_event_source('/some/source/')
    harness.set_event_source('/some/source/')
    harness.ignore_invalid_objects()
    harness.enable_event_repair('org.openvas.scan.ssl-certificate')
    return harness


def test_nist_pkits_host_certificate(harness):
    harness.process_xml(
        'host-certificate.xml',
        transcoder_root='/report/report/host',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.103692"]/../../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.ssl-certificate')) == 2

    cert_a, cert_b = harness.events.filter_type('org.openvas.scan.ssl-certificate')  # type: edxml.EDXMLEvent

    assert 'fingerprint' in cert_a
    assert len(cert_a['fingerprint']) == 1

    if cert_a['fingerprint'] != {'6f49779533d565e8b7c1062503eab41492c38e4d'}:
        tmp = cert_a
        cert_a = cert_b
        cert_b = tmp

    assert cert_a['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert cert_a['host-ipv4'] == {'10.0.0.1'}
    assert cert_a['valid-from'] == {'2010-01-01T08:30:00.000000Z'}
    assert cert_a['valid-until'] == {'2030-12-31T08:30:00.000000Z'}
    assert cert_a['fingerprint'] == {'6f49779533d565e8b7c1062503eab41492c38e4d'}
    assert cert_a['issuer-dn'] == {'C=US,O=Test Certificates 2011,CN=Trust Anchor'}
    assert cert_a['subject-dn'] == {'C=US,O=Test Certificates 2011,CN=Good CA'}
    assert cert_a['issuer-cn'] == {'Trust Anchor'}
    assert cert_a['subject-cn'] == {'Good CA'}
    assert cert_a['issuer-country'] == {'us'}
    assert cert_a['subject-country'] == {'us'}
    assert cert_a['issuer-organization'] == {'Test Certificates 2011'}
    assert cert_a['subject-organization'] == {'Test Certificates 2011'}

    assert cert_a.get_attachments()['certificate'].startswith('MIIDfDCCAm')

    assert cert_b['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert cert_b['host-ipv4'] == {'10.0.0.1'}
    assert cert_b['fingerprint'] == {'debfb496afdfc6b82440cf5dec9332a34ef83269'}
    assert cert_b['issuer-email'] == {'ca@trustwave.com'}
    assert cert_b['subject-province'] == {'Texas'}
    assert cert_b['subject-locality'] == {'austin'}
    assert cert_b['subject-domain'] == {'*.langui.sh', 'langui.sh', 'saseliminator.com', '*.saseliminator.com'}
    assert cert_b['host-name'] == {'langui.sh', 'saseliminator.com'}


def test_invalid_nist_pkits_host_certificate(harness, caplog):
    harness.process_xml(
        'invalid-host-certificate.xml',
        transcoder_root='/report/report/host',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.103692"]/../../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.ssl-certificate')) == 0
    assert 'Failed to process SSL certificate' in ''.join(caplog.messages)
