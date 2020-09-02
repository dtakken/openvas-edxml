#!/usr/bin/env python
# -*- coding: utf-8 -*-
from edxml.transcode.xml import XmlTranscoderMediator
from openvas_edxml.transcoders.error import OpenVasErrorTranscoder
from openvas_edxml.transcoders.host import OpenVasHostTranscoder
from openvas_edxml.transcoders.report import OpenVasReportTranscoder
from openvas_edxml.transcoders.result import OpenVasResultTranscoder


def register_transcoders(mediator, have_response_tag=False):
    """
    Registers the transcoders with a transcoder mediator.

    When parsing OpenVAS reports wrapped in a get_reports_response
    the have_response_tag must be set to True.

    Args:
        mediator (edxml.transcode.TranscoderMediator):
        have_response_tag (bool):
    """
    root = '/get_reports_response/report/report' if have_response_tag else '/report/report'

    mediator.register(root + '', OpenVasReportTranscoder)
    mediator.register(root + '/results/result', OpenVasResultTranscoder)
    mediator.register(root + '/host', OpenVasHostTranscoder)
    mediator.register(root + '/errors/error', OpenVasErrorTranscoder)
