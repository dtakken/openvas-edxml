import edxml

from edxml_bricks.generic import GenericBrick
from edxml.ontology import Brick
from edxml.ontology import DataType


class OpenVASBrick(Brick):
    """
    Brick that defines some object types and concepts specific to OpenVAS.
    """

    OBJECT_NVT_NAME = 'org.openvas.nvt.name'
    OBJECT_ERROR_MESSAGE = 'org.openvas.error-message'
    OBJECT_NVT_FAMILY = 'org.openvas.nvt.family'
    OBJECT_SCAN_NAME = 'org.openvas.scan.name'
    OBJECT_QOD_TYPE = 'org.openvas.result.detection.type'
    OBJECT_QOD_VALUE = 'org.openvas.result.detection.quality'
    OBJECT_SEVERITY = 'org.openvas.result.severity'
    OBJECT_THREAT = 'org.openvas.result.threat'
    OBJECT_IMPACT = 'org.openvas.result.impact'
    OBJECT_INSIGHT = 'org.openvas.result.insight'
    OBJECT_SOLUTION_TYPE = 'org.openvas.result.solution-type'

    CONCEPT_FINDING = GenericBrick.CONCEPT_ACT + '.discovery.finding.openvas-finding'

    # Known possible values of the QoD (Quality of Detection)
    # of an OpenVAS result.
    KNOWN_QOD_TYPES = (
        'exploit',
        'remote_vul',
        'remote_app',
        'package',
        'registry',
        'remote_active',
        'remote_banner',
        'executable_version',
        'remote_analysis',
        'remote_probe',
        'remote_banner_unreliable',
        'executable_version_unreliable',
        'general_note'
    )

    @classmethod
    def generate_object_types(cls, target_ontology):

        yield target_ontology.create_object_type(cls.OBJECT_NVT_NAME) \
            .set_description('a name of an OpenVAS plugin (NVT)')\
            .set_data_type(DataType.string(255))\
            .set_display_name('plugin name')

        yield target_ontology.create_object_type(cls.OBJECT_ERROR_MESSAGE) \
            .set_description('an error message produced by an OpenVAS plugin (NVT)')\
            .set_data_type(DataType.string(255))\
            .set_display_name('error message')

        yield target_ontology.create_object_type(cls.OBJECT_NVT_FAMILY) \
            .set_description('a name of a category of OpenVAS plugins')\
            .set_data_type(DataType.string(255))\
            .set_display_name('plugin family', 'plugin families')

        yield target_ontology.create_object_type(cls.OBJECT_SCAN_NAME) \
            .set_description('a name of an OpenVAS scan')\
            .set_data_type(DataType.string(255))\
            .set_display_name('scan name')

        yield target_ontology.create_object_type(cls.OBJECT_QOD_TYPE) \
            .set_description('an OpenVAS detection reliability indicator')\
            .set_data_type(DataType.enum('other', *cls.KNOWN_QOD_TYPES))\
            .set_display_name('QoD type')

        yield target_ontology.create_object_type(cls.OBJECT_QOD_VALUE) \
            .set_description('an OpenVAS detection reliability value, in percent')\
            .set_data_type(DataType.tiny_int(signed=False))\
            .set_unit('percent', '%')\
            .set_display_name('QoD value')

        yield target_ontology.create_object_type(cls.OBJECT_SEVERITY) \
            .set_description('a severity of an OpenVAS detection result')\
            .set_data_type(DataType.decimal(total_digits=3, fractional_digits=1))\
            .set_display_name('vulnerability severity', 'vulnerability severities')

        yield target_ontology.create_object_type(cls.OBJECT_THREAT) \
            .set_description('a threat level of an OpenVAS detection result')\
            .set_data_type(DataType.enum('high', 'medium', 'low', 'alarm', 'log', 'debug'))\
            .set_display_name('threat level')

        yield target_ontology.create_object_type(cls.OBJECT_IMPACT) \
            .set_description('a description of the impact of an issue detected by OpenVAS')\
            .set_data_type(DataType.string())\
            .set_display_name('impact description')\
            .compress()

        yield target_ontology.create_object_type(cls.OBJECT_INSIGHT)\
            .set_description('a technical detail about an issue detected by OpenVAS')\
            .set_data_type(DataType.string())\
            .set_display_name('issue detail')\
            .compress()

        yield target_ontology.create_object_type(cls.OBJECT_SOLUTION_TYPE)\
            .set_description('a type of solution for an issue detected by OpenVAS')\
            .set_data_type(DataType.string(255))\
            .set_display_name('solution type')\
            .set_regex_soft('Workaround|Mitigation|Vendor-Fix|None-Available|WillNotFix')

    @classmethod
    def generate_concepts(cls, target_ontology):

        yield target_ontology.create_concept(cls.CONCEPT_FINDING) \
            .set_display_name('OpenVAS finding') \
            .set_description('an OpenVAS detection result')


edxml.ontology.Ontology.register_brick(OpenVASBrick)
