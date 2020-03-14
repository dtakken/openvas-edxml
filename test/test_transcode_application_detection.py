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
    harness.enable_event_repair('org.openvas.scan.application-detection')
    return harness


def test_application_detection(harness):
    harness.process_xml(
        'application-detection.xml',
        transcoder_root='/report/report/host',
        element_root='detail/name[starts-with(text(),"cpe:/a:")]/..'
    )

    assert len(harness.events.filter_type('org.openvas.scan.application-detection')) == 2

    ports = {'22/tcp', '443/tcp', '80/tcp'}
    cpe = {'cpe:/a:openbsd:openssh:7.4p1', 'cpe:/a:apache:http_server:2.4.25'}

    for result in harness.events.filter_type('org.openvas.scan.application-detection'):  # type: edxml.EDXMLEvent
        assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
        assert result['host-ipv4'] == {'10.0.0.1'}
        assert result['port'].intersection(ports) != {}
        assert result['application'].intersection(cpe) != {}

        assert result.get_attachments() == {}
