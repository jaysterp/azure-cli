# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .run_request import RunRequest


class DockerBuildRequest(RunRequest):
    """The parameters for a docker quick build.

    :param arguments: The collection of override arguments to be used when
     executing the run.
    :type arguments: list[~containerregistrybuild.models.Argument]
    :param type: Constant filled by server.
    :type type: str
    :param image_names: The fully qualified image names including the
     repository and tag.
    :type image_names: list[str]
    :param is_push_enabled: The value of this property indicates whether the
     image built should be pushed to the registry or not. Default value: True .
    :type is_push_enabled: bool
    :param no_cache: The value of this property indicates whether the image
     cache is enabled or not. Default value: False .
    :type no_cache: bool
    :param docker_file_path: The Docker file path relative to the source
     location.
    :type docker_file_path: str
    :param source_location: The URL(absolute or relative) of the source that
     needs to be built. For Docker build, it can be an URL to a tar or github
     repoistory as supported by Docker.
     If it is relative URL, the relative path should be obtained from calling
     getSourceUploadUrl API.
    :type source_location: str
    :param timeout: Build timeout in seconds. Default value: 3600 .
    :type timeout: int
    :param platform: The platform properties against which the build will
     happen.
    :type platform: ~containerregistrybuild.models.PlatformProperties
    :param agent_configuration: The machine configuration of the build agent.
    :type agent_configuration: ~containerregistrybuild.models.AgentProperties
    """

    _validation = {
        'type': {'required': True},
        'docker_file_path': {'required': True},
        'source_location': {'required': True},
        'timeout': {'maximum': 28800, 'minimum': 300},
        'platform': {'required': True},
    }

    _attribute_map = {
        'arguments': {'key': 'arguments', 'type': '[Argument]'},
        'type': {'key': 'type', 'type': 'str'},
        'image_names': {'key': 'imageNames', 'type': '[str]'},
        'is_push_enabled': {'key': 'isPushEnabled', 'type': 'bool'},
        'no_cache': {'key': 'noCache', 'type': 'bool'},
        'docker_file_path': {'key': 'dockerFilePath', 'type': 'str'},
        'source_location': {'key': 'sourceLocation', 'type': 'str'},
        'timeout': {'key': 'timeout', 'type': 'int'},
        'platform': {'key': 'platform', 'type': 'PlatformProperties'},
        'agent_configuration': {'key': 'agentConfiguration', 'type': 'AgentProperties'},
    }

    def __init__(self, docker_file_path, source_location, platform, arguments=None, image_names=None, is_push_enabled=True, no_cache=False, timeout=3600, agent_configuration=None):
        super(DockerBuildRequest, self).__init__(arguments=arguments)
        self.image_names = image_names
        self.is_push_enabled = is_push_enabled
        self.no_cache = no_cache
        self.docker_file_path = docker_file_path
        self.source_location = source_location
        self.timeout = timeout
        self.platform = platform
        self.agent_configuration = agent_configuration
        self.type = 'DockerBuildRequest'
