from os.path import dirname
import pytest
from edxml.transcode.xml import XmlTranscoderTestHarness
from openvas_edxml import register_transcoders, OpenVasReportTranscoder


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(dirname(__file__) + '/fixtures', OpenVasReportTranscoder())
    register_transcoders(harness)
    harness.add_event_source('/some/source/')
    harness.set_event_source('/some/source/')
    return harness


def test_report(harness):
    harness.process_xml('report.xml', transcoder_root='/report/report')

    assert len(harness.events.filter_type('org.openvas.scan')) == 1

    result = harness.events.filter_type('org.openvas.scan')[0]

    assert result['id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['name'] == {'task name'}
    assert result['host-ipv4'] == {'10.0.0.1', '10.0.0.2'}
    assert result['host-count'] == {'3'}
    assert result['vuln-count'] == {'2'}
    assert result['time-start'] == {'2019-01-01T12:01:01.000000Z'}
    assert result['time-end'] == {'2019-01-02T12:01:01.000000Z'}


def test_incomplete_report(harness, caplog):
    harness.process_xml('incomplete-report.xml', transcoder_root='/report/report')

    assert len(harness.events.filter_type('org.openvas.scan')) == 1

    result = harness.events.filter_type('org.openvas.scan').pop()

    assert result['time-start'] == {'2019-01-01T12:01:01.000000Z'}
    assert 'time-end' not in result
    assert 'scan report is incomplete' in ''.join(caplog.messages)
