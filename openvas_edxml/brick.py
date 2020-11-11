#!/usr/bin/env python
# -*- coding: utf-8 -*-
import edxml

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
    OBJECT_QOD_TYPE = 'org.openvas.result.qod.type'
    OBJECT_QOD_VALUE = 'org.openvas.result.qod.value'
    OBJECT_SEVERITY = 'org.openvas.result.severity'
    OBJECT_THREAT = 'org.openvas.result.threat'
    OBJECT_SUMMARY = 'org.openvas.result.summary'
    OBJECT_IMPACT = 'org.openvas.result.impact'
    OBJECT_INSIGHT = 'org.openvas.result.insight'
    OBJECT_SOLUTION_TYPE = 'org.openvas.result.solution-type'
    OBJECT_XREF = 'org.openvas.result.xref'

    CONCEPT_VULNERABILITY = 'threat.vulnerability'
    CONCEPT_FINDING = 'openvas.finding'

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
            .set_description('name of an OpenVAS plugin (NVT)')\
            .set_data_type(DataType.string(255))\
            .set_display_name('OpenVAS plugin name')

        yield target_ontology.create_object_type(cls.OBJECT_ERROR_MESSAGE) \
            .set_description('error message produced by an OpenVAS plugin (NVT)')\
            .set_data_type(DataType.string(255))\
            .set_display_name('OpenVAS error message')

        yield target_ontology.create_object_type(cls.OBJECT_NVT_FAMILY) \
            .set_description('name of a category of OpenVAS plugins')\
            .set_data_type(DataType.string(255))\
            .set_display_name('OpenVAS plugin family', 'OpenVAS plugin families')

        yield target_ontology.create_object_type(cls.OBJECT_SCAN_NAME) \
            .set_description('name of an OpenVAS scan')\
            .set_data_type(DataType.string(255))\
            .set_display_name('OpenVAS scan name')

        yield target_ontology.create_object_type(cls.OBJECT_QOD_TYPE) \
            .set_description('OpenVAS detection reliability indicator')\
            .set_data_type(DataType.enum('other', *cls.KNOWN_QOD_TYPES))\
            .set_display_name('OpenVAS QoD type')

        yield target_ontology.create_object_type(cls.OBJECT_QOD_VALUE) \
            .set_description('OpenVAS detection reliability value, in percent')\
            .set_data_type(DataType.tiny_int(signed=False))\
            .set_display_name('OpenVAS QoD value')

        yield target_ontology.create_object_type(cls.OBJECT_SEVERITY) \
            .set_description('severity of an OpenVAS detection result')\
            .set_data_type(DataType.decimal(total_digits=3, fractional_digits=1))\
            .set_display_name('OpenVAS vulnerability severity', 'OpenVAS vulnerability severities')

        yield target_ontology.create_object_type(cls.OBJECT_THREAT) \
            .set_description('threat level of an OpenVAS detection result')\
            .set_data_type(DataType.enum('High', 'Medium', 'Low', 'Alarm', 'Log', 'Debug'))\
            .set_display_name('OpenVAS threat level')

        yield target_ontology.create_object_type(cls.OBJECT_SUMMARY) \
            .set_description('summary of an issue detected by OpenVAS')\
            .set_data_type(DataType.string())\
            .set_display_name('OpenVAS issue summary', 'OpenVAS issue summaries')

        yield target_ontology.create_object_type(cls.OBJECT_IMPACT) \
            .set_description('description of the impact of an issue detected by OpenVAS')\
            .set_data_type(DataType.string())\
            .set_display_name('OpenVAS impact description')

        yield target_ontology.create_object_type(cls.OBJECT_INSIGHT)\
            .set_description('technical details about an issue detected by OpenVAS')\
            .set_data_type(DataType.string())\
            .set_display_name('OpenVAS issue detail')

        yield target_ontology.create_object_type(cls.OBJECT_SOLUTION_TYPE)\
            .set_description('type of solution for an issue detected by OpenVAS')\
            .set_data_type(DataType.string(255))\
            .set_display_name('OpenVAS solution type')

        yield target_ontology.create_object_type(cls.OBJECT_XREF) \
            .set_description('URL to reference material about an issue detected by OpenVAS')\
            .set_data_type(DataType.uri())\
            .set_display_name('OpenVAS cross reference')

    @classmethod
    def generate_concepts(cls, target_ontology):

        yield target_ontology.create_concept(cls.CONCEPT_FINDING) \
            .set_display_name('OpenVAS finding') \
            .set_description('OpenVAS detection result')

        # This is an extension of the 'threat' concept from
        # the computer security brick.
        yield target_ontology.create_concept(cls.CONCEPT_VULNERABILITY) \
            .set_display_name('vulnerability', 'vulnerabilities') \
            .set_description('security defect reducing a systems\'s information assurance')


edxml.ontology.Ontology.register_brick(OpenVASBrick)
