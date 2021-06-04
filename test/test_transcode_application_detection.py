from os.path import dirname

import pytest

from edxml.transcode.xml import XmlTranscoderTestHarness
from openvas_edxml import register_transcoders, OpenVasHostTranscoder


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(
        fixtures_path=dirname(__file__) + '/fixtures',
        transcoder=OpenVasHostTranscoder(),
        transcoder_root='/report/report/host',
        register=False
    )
    register_transcoders(harness)
    return harness


def test_application_detection(harness):
    harness.process_xml(
        'application-detection.xml',
        element_root='detail/name[starts-with(text(),"cpe:/a:")]/..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.application-detection')) == 2

    ports = {'22/tcp', '443/tcp', '80/tcp'}
    cpe = {'cpe:/a:openbsd:openssh:7.4p1', 'cpe:/a:apache:http_server:2.4.25'}

    for result in harness.events.filter_type('org.openvas.scan.application-detection'):
        assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
        assert result['time'] == {'2019-01-01T12:01:01.000000Z'}
        assert result['host.ipv4'] == {'10.0.0.1'}
        assert result['port'].intersection(ports) != {}
        assert result['application'].intersection(cpe) != {}

        assert result.get_attachments() == {}


def test_application_detection_ipv6(harness):
    harness.process_xml(
        'application-detection-ipv6.xml',
        element_root='detail/name[starts-with(text(),"cpe:/a:")]/..'
    )

    for result in harness.events.filter_type('org.openvas.scan.application-detection'):
        assert result['host.ipv6'] == {'2001:0db8:0000:0000:0000:8a2e:0370:7334'}
