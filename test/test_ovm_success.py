from os.path import dirname

import pytest
from edxml.transcode.xml import XmlTranscoderTestHarness

from openvas_edxml import register_transcoders, OpenVasReportTranscoder


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(
        fixtures_path=dirname(__file__) + '/fixtures',
        transcoder=OpenVasReportTranscoder(),
        transcoder_root='/get_reports_response/report/report',
        register=False
    )
    register_transcoders(harness, have_response_tag=True)
    return harness


def test_parse_response_tag(harness):
    harness.process_xml('ovm-success-response.xml')

    assert len(harness.events) > 0
