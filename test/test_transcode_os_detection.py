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
        'os-detection.xml',
        transcoder_root='/report/report/host',
        element_root='detail/name[starts-with(text(),"cpe:/o:")]/../..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.os-detection')) == 1

    result = harness.events.filter_type('org.openvas.scan.os-detection').pop()

    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['host-ipv4'] == {'10.0.0.1'}
    assert result['os'] == {'cpe:/o:debian:debian_linux:9', 'cpe:/o:linux:kernel:2.6.10'}

    assert result.get_attachments() == {}


def test_os_detection_ipv6(harness):
    harness.process_xml(
        'os-detection-ipv6.xml',
        transcoder_root='/report/report/host',
        element_root='detail/name[starts-with(text(),"cpe:/o:")]/../..'
    )

    result = harness.events.filter_type('org.openvas.scan.os-detection').pop()

    assert result['host-ipv6'] == {'2001:0db8:0000:0000:0000:8a2e:0370:7334'}
