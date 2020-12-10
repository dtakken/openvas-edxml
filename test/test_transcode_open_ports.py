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


def test_open_port_detection(harness):
    harness.process_xml(
        'open-ports.xml',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.900239"]/../../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.open-ports')) == 1

    result = harness.events.filter_type('org.openvas.scan.open-ports').pop()

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['host.ipv4'] == {'10.0.0.1'}
    assert result['port'] == {'443/TCP', '22/TCP', '80/TCP'}

    assert result.get_attachments() == {}


def test_open_port_detection_ipv6(harness):
    harness.process_xml(
        'open-ports-ipv6.xml',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.900239"]/../../..'
    )

    result = harness.events.filter_type('org.openvas.scan.open-ports').pop()

    assert result['host.ipv6'] == {'2001:0db8:0000:0000:0000:8a2e:0370:7334'}
