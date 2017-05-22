#!/usr/bin/env python
# -*- coding: utf-8 -*-
from edxml.transcode.xml import XmlTranscoderMediator
from openvas_edxml.transcoders.report import OpenVasReportTranscoder
from openvas_edxml.transcoders.result import OpenVasResultTranscoder


def registerTranscoders():
  XmlTranscoderMediator.Register('/get_reports_response/report/report', OpenVasReportTranscoder)
  XmlTranscoderMediator.Register('/get_reports_response/report/report/results/result', OpenVasResultTranscoder)
