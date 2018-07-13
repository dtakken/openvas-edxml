#!/usr/bin/env python
# -*- coding: utf-8 -*-
import edxml

from edxml.ontology import Brick
from edxml.ontology import DataType


class OpenVASBrick(Brick):
    """
    Class that defines some object types specific to OpenVAS.
    """

    OBJECT_NVT_OID = 'org.openvas.nvt.iod'
    OBJECT_NVT_NAME = 'org.openvas.nvt.name'
    OBJECT_NVT_FAMILY = 'org.openvas.nvt.family'
    OBJECT_SCAN_NAME = 'org.openvas.scan.name'
    OBJECT_QOD_TYPE = 'org.openvas.result.qod.type'
    OBJECT_QOD_VALUE = 'org.openvas.result.qod.value'
    OBJECT_SEVERITY = 'org.openvas.result.severity'
    OBJECT_THREAT = 'org.openvas.result.threat'
    OBJECT_SUMMARY = 'org.openvas.result.summary'
    OBJECT_AFFECTS = 'org.openvas.result.affects'
    OBJECT_IMPACT = 'org.openvas.result.impact'
    OBJECT_INSIGHT = 'org.openvas.result.insight'
    OBJECT_SOLUTION = 'org.openvas.result.solution'
    OBJECT_SOLUTION_TYPE = 'org.openvas.result.solutiontype'
    OBJECT_XREF = 'org.openvas.result.xref'

    CONCEPT_VULNERABILITY = 'threat.vulnerability'

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
    def generateObjectTypes(cls, targetOntology):

        yield targetOntology.CreateObjectType(cls.OBJECT_NVT_OID)\
                            .SetDescription('identifier of an OpenVAS plugin (NVT)')\
                            .SetDataType(DataType.String(255, CaseSensitive=False, RequireUnicode=False))\
                            .SetDisplayName('OpenVAS plugin identifier')

        yield targetOntology.CreateObjectType(cls.OBJECT_NVT_NAME)\
                            .SetDescription('name of an OpenVAS plugin (NVT)')\
                            .SetDataType(DataType.String(255))\
                            .SetDisplayName('OpenVAS plugin name')

        yield targetOntology.CreateObjectType(cls.OBJECT_NVT_FAMILY)\
                            .SetDescription('name of a category of OpenVAS plugins')\
                            .SetDataType(DataType.String(255))\
                            .SetDisplayName('OpenVAS plugin family', 'OpenVAS plugin families')

        yield targetOntology.CreateObjectType(cls.OBJECT_SCAN_NAME)\
                            .SetDescription('name of an OpenVAS scan')\
                            .SetDataType(DataType.String(255))\
                            .SetDisplayName('OpenVAS scan name')

        yield targetOntology.CreateObjectType(cls.OBJECT_QOD_TYPE)\
                            .SetDescription('OpenVAS detection reliability indicator')\
                            .SetDataType(DataType.Enum('other', *cls.KNOWN_QOD_TYPES))\
                            .SetDisplayName('OpenVAS QoD type')

        yield targetOntology.CreateObjectType(cls.OBJECT_QOD_VALUE)\
                            .SetDescription('OpenVAS detection reliability value, in percent')\
                            .SetDataType(DataType.TinyInt(Signed=False))\
                            .SetDisplayName('OpenVAS QoD value')

        yield targetOntology.CreateObjectType(cls.OBJECT_SEVERITY)\
                            .SetDescription('severity of an OpenVAS detection result')\
                            .SetDataType(DataType.Decimal(3, 1, Signed=False))\
                            .SetDisplayName('OpenVAS vulnerability severity', 'OpenVAS vulnerability severities')

        yield targetOntology.CreateObjectType(cls.OBJECT_THREAT)\
                            .SetDescription('threat level of an OpenVAS detection result')\
                            .SetDataType(DataType.Enum('High', 'Medium', 'Low', 'Alarm', 'Log', 'Debug'))\
                            .SetDisplayName('OpenVAS threat level')

        yield targetOntology.CreateObjectType(cls.OBJECT_SUMMARY)\
                            .SetDescription('summary of an issue detected by OpenVAS')\
                            .SetDataType(DataType.String())\
                            .SetDisplayName('OpenVAS issue summary', 'OpenVAS issue summaries')

        yield targetOntology.CreateObjectType(cls.OBJECT_AFFECTS)\
                            .SetDescription('description of the scope of affected systems of an OpenVAS '
                                            'security issue')\
                            .SetDataType(DataType.String())\
                            .SetDisplayName('affected systems description')

        yield targetOntology.CreateObjectType(cls.OBJECT_IMPACT)\
                            .SetDescription('description of the impact of an issue detected by OpenVAS')\
                            .SetDataType(DataType.String())\
                            .SetDisplayName('OpenVAS impact description')

        yield targetOntology.CreateObjectType(cls.OBJECT_INSIGHT)\
                            .SetDescription('technical details about an issue detected by OpenVAS')\
                            .SetDataType(DataType.String())\
                            .SetDisplayName('OpenVAS issue details')

        yield targetOntology.CreateObjectType(cls.OBJECT_SOLUTION)\
                            .SetDescription('proposed solution for an issue detected by OpenVAS')\
                            .SetDataType(DataType.String())\
                            .SetDisplayName('OpenVAS issue solution')

        yield targetOntology.CreateObjectType(cls.OBJECT_SOLUTION_TYPE)\
                            .SetDescription('type of solution for an issue detected by OpenVAS')\
                            .SetDataType(DataType.String(255))\
                            .SetDisplayName('OpenVAS solution type')

        yield targetOntology.CreateObjectType(cls.OBJECT_XREF)\
                            .SetDescription('URL to reference material about an issue detected by OpenVAS')\
                            .SetDataType(DataType.Uri())\
                            .SetDisplayName('OpenVAS cross reference')

    @classmethod
    def generateConcepts(cls, targetOntology):

        # This is an extension of the 'threat' concept from
        # the computer security brick.
        yield targetOntology.CreateConcept(cls.CONCEPT_VULNERABILITY)\
            .SetDisplayName('vulnerability', 'vulnerabilities')\
            .SetDescription('security defect reducing a systems\'s information assurance')


edxml.ontology.Ontology.RegisterBrick(OpenVASBrick)
