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


def test_nvt_listings(harness):
    harness.process_xml(
        'nvt-listing.xml',
        transcoder_root='/report/report/host',
        element_root='detail/name[text() = "EXIT_CODE"]/../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.nvt')) == 1

    result = harness.events.filter_type('org.openvas.scan.nvt').pop()  # type: edxml.EDXMLEvent

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['host-ipv4'] == {'10.0.0.1'}
    assert result['nvt-oid'] == {'1.3.6.1.4.1.25623.1.0.103028', '1.3.6.1.4.1.25623.1.0.803197'}

    assert result.get_attachments() == {}
