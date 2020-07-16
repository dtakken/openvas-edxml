from io import BytesIO
from os.path import dirname

import pytest

from openvas_edxml import register_transcoders
from openvas_edxml.cli import OpenVasTranscoderMediator


def test_application_detection():
    with pytest.raises(ValueError, match='error response status: 404'):
        mediator = OpenVasTranscoderMediator(BytesIO(), source_uri='/some/source/', have_response_tag=True)
        register_transcoders(mediator, have_response_tag=True)
        mediator.parse(dirname(__file__) + '/fixtures/ovm-error-response.xml')
