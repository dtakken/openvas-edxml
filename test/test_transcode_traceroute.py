from os.path import dirname

import pytest

import edxml
from edxml.transcode.test_harness import TranscoderTestHarness
from edxml.transcode.xml import XmlTranscoderTestHarness
from openvas_edxml import register_transcoders, OpenVasHostTranscoder

TranscoderTestHarness.clear_registrations()
register_transcoders(TranscoderTestHarness)


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(dirname(__file__) + '/fixtures', OpenVasHostTranscoder())
    harness.add_event_source('/some/source/')
    harness.set_event_source('/some/source/')
    harness.ignore_invalid_objects()
    return harness


def test_traceroute(harness):
    harness.process_xml(
        'traceroute.xml',
        transcoder_root='/report/report/host',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.51662"]/../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.routers')) == 1

    result = harness.events.filter_type('org.openvas.scan.routers').pop()  # type: edxml.EDXMLEvent

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['scanner-ipv4'] == {'192.168.0.1'}
    assert result['router-ipv4'] == {'10.0.0.1'}

    assert result.get_attachments() == {}