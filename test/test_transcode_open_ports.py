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


def test_application_detection(harness):
    harness.process_xml(
        'open-ports.xml',
        transcoder_root='/report/report/host',
        element_root='detail/source/name[text() = "1.3.6.1.4.1.25623.1.0.900239"]/../../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.open-ports')) == 1

    result = harness.events.filter_type('org.openvas.scan.open-ports').pop()

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['host-ipv4'] == {'10.0.0.1'}
    assert result['port'] == {'443/tcp', '22/tcp', '80/tcp'}

    assert result.get_attachments() == {}
