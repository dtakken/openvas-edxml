from os.path import dirname

import pytest

from edxml.transcode.xml import XmlTranscoderTestHarness
from openvas_edxml import register_transcoders, OpenVasHostTranscoder


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(dirname(__file__) + '/fixtures', OpenVasHostTranscoder())
    register_transcoders(harness)
    harness.add_event_source('/some/source/')
    harness.set_event_source('/some/source/')
    return harness


def test_traceroute(harness):
    harness.process_xml(
        'traceroute.xml',
        transcoder_root='/report/report/host',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.51662"]/../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.routers')) == 1

    result = harness.events.filter_type('org.openvas.scan.routers').pop()

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['scanner-ipv4'] == {'192.168.0.1'}
    assert result['router-ipv4'] == {'10.0.0.1'}

    assert result.get_attachments() == {}


def test_traceroute_ipv6(harness):
    harness.process_xml(
        'traceroute-ipv6.xml',
        transcoder_root='/report/report/host',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.51662"]/../..'
    )

    result = harness.events.filter_type('org.openvas.scan.routers').pop()

    assert result['scanner-ipv6'] == {'0000:0000:0000:0000:0000:ffff:c0a8:0001'}
    assert result['router-ipv6'] == {'0000:0000:0000:0000:0000:ffff:0a00:0001'}

    assert result.get_attachments() == {}
