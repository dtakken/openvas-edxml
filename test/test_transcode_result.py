from os.path import dirname

import pytest

from edxml.transcode.xml import XmlTranscoderTestHarness
from openvas_edxml import OpenVasResultTranscoder, register_transcoders


@pytest.fixture()
def harness():
    harness = XmlTranscoderTestHarness(dirname(__file__) + '/fixtures', OpenVasResultTranscoder())
    register_transcoders(harness)
    harness.add_event_source('/some/source/')
    harness.set_event_source('/some/source/')
    return harness


def test_result(harness):
    harness.process_xml('result.xml', transcoder_root='/report/report/results/result')

    assert len(harness.events.filter_type('org.openvas.scan.nvt')) == 1
    assert len(harness.events.filter_type('org.openvas.scan.result')) == 1

    result = harness.events.filter_type('org.openvas.scan.result').pop()

    assert result['id'] == {'d37be786-a052-433e-9ecf-28babfaea2ac'}
    assert result['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert result['nvt-oid'] == {'1.3.6.1.4.1.25623.1.0.112081'}
    assert result['nvt-name'] == {'HTTP Security Headers Detection'}
    assert result['nvt-family'] == {'General'}
    assert result['cvss-score'] == {'5.0'}
    assert result['time'] == {'2019-01-02T12:01:01.000000Z'}
    assert result['severity'] == {'6.0'}
    assert result['threat'] == {'Log'}
    assert result['host-ipv4'] == {'10.0.0.1'}
    assert result['port'] == {'443/TCP'}
    assert result['qod-type'] == {'remote_banner'}
    assert result['qod-value'] == {'80'}
    assert result['cvss-base'] == {'AV:N/AC:L/Au:N/C:N/I:N/A:N'}
    assert result['solution-type'] == {'Test solution type'}
    assert result['xref'] == {'http://test1/', 'http://test2/'}
    assert result['insight'] == {'Test insight'}
    assert result['impact'] == {'Test impact'}
    assert result['cve'] == {'CVE-2014-3566', 'CVE-2016-0800'}
    assert result['bid'] == {'9506', '9561'}

    assert result.get_attachments()['description'] == 'Test description'
    assert result.get_attachments()['solution'] == 'Test solution  '
    assert result.get_attachments()['affected'] == '  Test affected '
    assert result.get_attachments()['summary'] == 'Test summary  '
    assert result.get_attachments()['input-xml-element'].startswith('<result id="d37be786-a052-433e-9ecf-28babfaea2ac"')

    nvt = harness.events.filter_type('org.openvas.scan.nvt')[0]

    assert nvt['scan-id'] == {'fb167629-3bdf-4ab1-ae7d-c64a0d7ad595'}
    assert nvt['nvt-oid'] == {'1.3.6.1.4.1.25623.1.0.112081'}
    assert nvt['host-ipv4'] == {'10.0.0.1'}


def test_result_ipv6(harness):
    harness.process_xml('result-ipv6.xml', transcoder_root='/report/report/results/result')

    assert len(harness.events.filter_type('org.openvas.scan.nvt')) == 1
    assert len(harness.events.filter_type('org.openvas.scan.result')) == 1

    result = harness.events.filter_type('org.openvas.scan.result')[0]

    assert result['host-ipv6'] == {'2001:0db8:0000:0000:0000:8a2e:0370:7334'}

    nvt = harness.events.filter_type('org.openvas.scan.nvt')[0]

    assert nvt['host-ipv6'] == {'2001:0db8:0000:0000:0000:8a2e:0370:7334'}


def test_result_non_numeric_port(harness):
    harness.process_xml('result-non-numerical-port.xml', transcoder_root='/report/report/results/result')

    assert len(harness.events.filter_type('org.openvas.scan.nvt')) == 1
    assert len(harness.events.filter_type('org.openvas.scan.result')) == 1

    result = harness.events.filter_type('org.openvas.scan.result')[0]

    assert result['port'] == set()


def test_result_terse(harness):
    harness.process_xml('result-terse.xml', transcoder_root='/report/report/results/result')

    # No need to add any assertions here, we only test that a result that is
    # missing a lot of information will transcode without any errors.
