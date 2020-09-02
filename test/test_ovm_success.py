from os.path import dirname

import pytest
from edxml.transcode.xml import XmlTranscoderTestHarness

from openvas_edxml import register_transcoders, OpenVasResultTranscoder, OpenVasReportTranscoder


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(dirname(__file__) + '/fixtures', OpenVasReportTranscoder())
    register_transcoders(harness, have_response_tag=True)
    harness.add_event_source('/some/source/')
    harness.set_event_source('/some/source/')
    return harness


def test_parse_response_tag(harness):
    harness.process_xml('ovm-success-response.xml', transcoder_root='/get_reports_response/report/report')

    assert len(harness.events) > 0
