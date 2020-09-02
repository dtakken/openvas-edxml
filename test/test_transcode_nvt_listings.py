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


def test_nvt_listings(harness):
    harness.process_xml(
        'nvt-listing.xml',
        transcoder_root='/report/report/host',
        element_root='detail/name[text() = "EXIT_CODE"]/../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.nvt')) == 1

    result = harness.events.filter_type('org.openvas.scan.nvt').pop()

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['host-ipv4'] == {'10.0.0.1'}
    assert result['nvt-oid'] == {'1.3.6.1.4.1.25623.1.0.103028', '1.3.6.1.4.1.25623.1.0.803197'}

    assert result.get_attachments() == {}


def test_nvt_listings_ipv6(harness):
    harness.process_xml(
        'nvt-listing-ipv6.xml',
        transcoder_root='/report/report/host',
        element_root='detail/name[text() = "EXIT_CODE"]/../..'
    )

    result = harness.events.filter_type('org.openvas.scan.nvt').pop()

    assert result['host-ipv6'] == {'2001:0db8:0000:0000:0000:8a2e:0370:7334'}
