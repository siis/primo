# Copyright (C) 2015 The Pennsylvania State University and the University of Wisconsin
# Systems and Internet Infrastructure Security Laboratory
#
# Author: Damien Octeau
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module for fetching data from protobufs."""

from google.protobuf import text_format
import logging
import os

from primo.linking import applications
from primo.linking import ic3_data_pb2


LOGGER = logging.getLogger(__name__)


exit_point_count = 0
intent_count = 0
intent_filter_count = 0


def FetchData(protobufs, protodirs, validate):
  """Fetches data from disk.

  Args:
    protobufs: A list of paths to protobufs.
    protodirs: A list of paths to directories containing protobufs.
    validate: True if validation is being performed.

  Returns: A tuple with the set of applications, the set of components, the list
  of Intents and the set of Intent Filters.
  """

  apps = set()
  components = set()
  intents = []
  intent_filters = set()

  if protobufs:
    for file_path in protobufs:
      ProcessFile(file_path, apps, components, intents, intent_filters,
                  validate)

  if protodirs:
    for directory in protodirs:
      for file_path in os.listdir(directory):
        ProcessFile(os.path.join(directory, file_path), apps, components,
                    intents, intent_filters, validate)

  print 'Applications: %s' % len(apps)
  print 'Exit points: %s' % exit_point_count
  print 'Intents: %s' % intent_count
  print 'Intent filters: %s' % intent_filter_count
  return apps, components, intents, intent_filters


def ProcessFile(file_path, apps, components, intents, intent_filters, validate):
  """Loads a single protobuf.

  Args:
    file_path: The path to a protobuf.
    apps: The set of applications.
    components: The set of components.
    intents: The list of Intents.
    intent_filters: The set of Intent Filters.
    validate: True if validation is being performed.
  """

  LOGGER.debug('Loading %s.', file_path)
  if os.path.islink(file_path):
    linked_path = os.readlink(file_path)
    file_path = (linked_path if os.path.isabs(linked_path)
                 else os.path.join(os.path.dirname(file_path), linked_path))
  file_contents_string = None
  with open(file_path) as in_file:
    file_contents_string = in_file.read()

  application = ic3_data_pb2.Application()
  if file_path.endswith('.txt'):
    text_format.Merge(file_contents_string, application)
  else:
    application.ParseFromString(file_contents_string)

  application_wrapper = applications.MakeApplication(application, validate)
  global exit_point_count
  exit_point_count += application_wrapper.exit_point_count
  global intent_count
  intent_count += application_wrapper.intent_count
  global intent_filter_count
  intent_filter_count += application_wrapper.intent_filter_count

  apps.add(application_wrapper)
  intents += application_wrapper.intents
  for component in application_wrapper.components:
    components.add(component)
    for intent_filter in component.filters:
      intent_filters.add(intent_filter)
