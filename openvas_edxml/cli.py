#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import openvas_edxml

from datetime import datetime
from typing import Optional
from dateutil.parser import parse
from edxml.transcode.xml import XmlTranscoderMediator


class OpenVasTranscoderMediator(XmlTranscoderMediator):
    """
    This extension of the XmlTranscoderMediator is mainly used to generate a
    suitable EDXML source definition for the scan results. It also checks for
    OMP error responses that indicate report download failures.
    """
    def __init__(self, output, source_uri=None, source_desc=None,
                 have_response_tag=False):
        super(OpenVasTranscoderMediator, self).__init__(output)
        self.__time_of_first_result = None  # type: Optional[datetime]
        self.__found_response_tag = False
        self.__source_uri = source_uri or '/org/openvas/scans/'
        self.__source_desc = source_desc or 'OpenVAS scan data'
        self.__have_response_tag = have_response_tag

    def process(self, element, tree=None):

        if self.__have_response_tag and element.tag == 'report':
            # Report is wrapped into a response tag allowing us to
            # check if the reponse actually contains a successful
            # response. This means that we will error when parsing
            # a failed report fetch response in stead of outputting
            # an empty EDXML file.
            response_element = element.getparent().getparent()
            if response_element is not None:
                self.__found_response_tag = True
                if response_element.attrib['status'] != '200':
                    raise ValueError(
                        'OpenVAS report contains a server error response status: %s' %
                        response_element.attrib['status']
                    )

        scan_start = element.find('creation_time')

        if self.__time_of_first_result is None and scan_start is not None:
            # Ok, we just found the first result entry in the
            # input. We can use it to generate an event source
            # definition. Note that the report element is not
            # processed first, because processing only takes
            # place after the closing tag has been read.
            self.__time_of_first_result = parse(scan_start.text)
            source = self._create_source(element)

            # We set the source URI that we just added to allow the mediator
            # to automatically set it for all output events.
            self.add_event_source(source.get_uri())
            self.set_event_source(source.get_uri())

        return super(OpenVasTranscoderMediator, self).process(element, tree)

    def _create_source(self, element):
        """
        Create a EDXML source definition describing the scan. The method can be
        overridden to create a custom URI scheme. The XML <report> element is
        passed to allow incorporating information from it into the source
        definition.

        Args:
            element (etree.Element):

        Returns:
            edxml.ontology.EventSource

        """
        return self._ontology.create_event_source(
                    self.__source_uri, self.__source_desc, datetime.now().strftime('%Y%m%d')
                )

    def found_response_tag(self):
        return self.__found_response_tag


def main():
    arg_parser = argparse.ArgumentParser(description='This tool produces EDXML data streams from OpenVAS XML reports.')

    arg_parser.add_argument(
        '--uri', '-u', help='The EDXML source URI that will be associated with the scan data.'
    )
    arg_parser.add_argument(
        '--verbose', '-v', action='count', help='Increments the output verbosity of logging messages on standard error.'
    )
    arg_parser.add_argument(
        '--quiet', '-q', action='store_true', help='Suppresses all logging messages except for errors.'
    )
    arg_parser.add_argument(
        '--desc', '-d', help='The description of the EDXML source that will be associated with the scan data.'
    )
    arg_parser.add_argument(
        '--file', '-f', nargs=1, help='By default OpenVAS data is read from standard input. When this option is used '
                                      'input will be read from the file at specified path.'
    )
    arg_parser.add_argument(
        '--dump-ontology', action='store_true', help='Output EDXML containing only the ontology.'
    )
    arg_parser.add_argument(
        '--dump-description', action='store_true', help='Output reStructuredText describing this transcoder.'
    )
    arg_parser.add_argument(
        '--have-response-tag', "-r", action='store_true',
        help='Use this option for OpenVAS XML data that is wrapped inside a <get_reports_response> tag.'
    )
    args = arg_parser.parse_args()

    if args.file:
        openvas_input = args.file[0]
    else:
        openvas_input = sys.stdin.buffer

    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())

    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        if args.verbose > 0:
            logger.setLevel(logging.INFO)
        if args.verbose > 1:
            logger.setLevel(logging.DEBUG)

    if args.dump_description:
        with OpenVasTranscoderMediator(open(os.devnull, 'wb'), args.uri, args.desc, args.have_response_tag) as mediator:
            openvas_edxml.register_transcoders(mediator, args.have_response_tag)
            print(mediator.describe_transcoder('`OpenVAS <http://www.openvas.org/>`_ XML reports'))
        return

    with OpenVasTranscoderMediator(sys.stdout.buffer, args.uri, args.desc, args.have_response_tag) as mediator:
        openvas_edxml.register_transcoders(mediator, args.have_response_tag)

        mediator.debug(warn_fallback=False, warn_no_transcoder=False)
        mediator.ignore_invalid_objects()
        if not args.dump_ontology:
            mediator.parse(openvas_input)
            if args.have_response_tag and not mediator.found_response_tag():
                raise Exception('OpenVAS report does not contain the expected <get_reports_response> tag.')


if __name__ == "__main__":
    main()
