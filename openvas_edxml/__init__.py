#!/usr/bin/env python
# -*- coding: utf-8 -*-
from edxml.transcode.xml import XmlTranscoderMediator
from openvas_edxml.transcoders.host import OpenVasHostTranscoder
from openvas_edxml.transcoders.report import OpenVasReportTranscoder
from openvas_edxml.transcoders.result import OpenVasResultTranscoder


def register_transcoders():
    XmlTranscoderMediator.register('/get_reports_response/report/report', OpenVasReportTranscoder)
    XmlTranscoderMediator.register('/get_reports_response/report/report/results/result', OpenVasResultTranscoder)
    XmlTranscoderMediator.register('/get_reports_response/report/report/host', OpenVasHostTranscoder)
