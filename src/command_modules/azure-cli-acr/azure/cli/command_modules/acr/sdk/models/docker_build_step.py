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

from .task_step_properties import TaskStepProperties


class DockerBuildStep(TaskStepProperties):
    """The Docker build step.

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
     context.
    :type docker_file_path: str
    :param context_path: The URL(absolute or relative) of the source context
     for the build task.
     If it is relative, the context will be relative to the source repository
     URL of the build task.
    :type context_path: str
    :param arguments: The collection of override arguments to be used when
     executing this build step.
    :type arguments: list[~containerregistrybuild.models.Argument]
    :param base_image_dependencies: List of base image dependencies for a
     step.
    :type base_image_dependencies:
     list[~containerregistrybuild.models.BaseImageDependency]
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'image_names': {'key': 'imageNames', 'type': '[str]'},
        'is_push_enabled': {'key': 'isPushEnabled', 'type': 'bool'},
        'no_cache': {'key': 'noCache', 'type': 'bool'},
        'docker_file_path': {'key': 'dockerFilePath', 'type': 'str'},
        'context_path': {'key': 'contextPath', 'type': 'str'},
        'arguments': {'key': 'arguments', 'type': '[Argument]'},
        'base_image_dependencies': {'key': 'baseImageDependencies', 'type': '[BaseImageDependency]'},
    }

    def __init__(self, image_names=None, is_push_enabled=True, no_cache=False, docker_file_path=None, context_path=None, arguments=None, base_image_dependencies=None):
        super(DockerBuildStep, self).__init__()
        self.image_names = image_names
        self.is_push_enabled = is_push_enabled
        self.no_cache = no_cache
        self.docker_file_path = docker_file_path
        self.context_path = context_path
        self.arguments = arguments
        self.base_image_dependencies = base_image_dependencies
        self.type = 'Docker'
