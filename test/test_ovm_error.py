from io import BytesIO
from os.path import dirname

import pytest

from openvas_edxml import register_transcoders
from openvas_edxml.cli import OpenVasTranscoderMediator

register_transcoders(OpenVasTranscoderMediator, have_response_tag=True)


def test_application_detection():
    with pytest.raises(ValueError, match='error response status: 404'):
        mediator = OpenVasTranscoderMediator(BytesIO(), source_uri='/some/source/', have_response_tag=True)
        mediator.parse(dirname(__file__) + '/fixtures/ovm-error-response.xml')
