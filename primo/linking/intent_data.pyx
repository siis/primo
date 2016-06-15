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
"""Global Intent maps and constants."""

from primo.linking.intents cimport ComponentIntent
from primo.linking.intents cimport Intent

import logging

from primo.linking.target_data import BASE_TYPE
from primo.linking.target_data import CLASS
from primo.linking.target_data import PACKAGE
from primo.linking import ic3_data_pb2

include 'primo/linking/constants.pxi'


LOGGER = logging.getLogger(__name__)


# Yields all Intents that have a field with a given value.
cdef dict _ATTRIBUTE_MAPS = {'action': {},
                             'categories': {},
                             'scheme': {},
                             'host': {},
                             'port': {},
                             'path': {},
                             'dtype': {},
                             'dpackage': {},
                             'dclass': {},
                             BASE_TYPE: {}}

cdef set _PRECISE_INTENTS = set()
cdef set _IMPRECISE_INTENTS = set()
cdef set _PRECISE_COMPONENT_INTENTS = set()
cdef set _IMPRECISE_COMPONENT_INTENTS = set()


cdef void AddAttribute(object field_value, Intent intent, dict attribute_map):
  """Helper function that adds an Intent to an Intent attribute map.

  Args:
    field_value: A field value.
    intent: An Intent.
    attribute_map: A map that associates field values with the Intents that have
    them.
  """

  cdef set end_points = attribute_map.get(field_value)
  if not end_points:
    end_points = set()
    attribute_map[field_value] = end_points
  end_points.add(intent)


cdef void AddAttributesForPreciseIntent(Intent intent):
  """Adds attributes for a precise Intent to training data.

  Args:
    intent: An Intent.
  """

  cdef str attribute_type
  cdef dict attribute_map
  for attribute_type, attribute_map in _ATTRIBUTE_MAPS.iteritems():
    if attribute_type == BASE_TYPE:
      # BASE_TYPE is not a real field.
      continue
    field_value = getattr(intent, attribute_type)
    if (attribute_type == 'dtype' and field_value and field_value != '*/*'
        and field_value.endswith('/*')):
      base_type = field_value.split('/', 1)[0]
      AddAttribute(base_type, intent, attribute_map)
    AddAttribute(field_value, intent, attribute_map)


cdef void AddPreciseIntent(ComponentIntent intent):
  """Adds a precise Intent to the sets of precise Intents and updates training
  data.

  Even if the Intent is already in the sets, we still use it as training data.
  That is because it will not create a new link (as all linking fields are the
  same as a previously inserted Intent from the same exit point), but it still
  gives additional data about the prevalence of a given Intent pattern.

  Args:
    intent: A ComponentIntent object.
  """

  AddAttributesForPreciseIntent(intent.intent)
  if intent not in _PRECISE_COMPONENT_INTENTS:
    _PRECISE_INTENTS.add(intent.intent)
    _PRECISE_COMPONENT_INTENTS.add(intent)


cdef void AddImpreciseIntent(ComponentIntent intent):
  """Adds an imprecise Intent to the sets of imprecise Intents.

  Args:
    intent: A ComponentIntent object.
  """

  if intent not in _IMPRECISE_COMPONENT_INTENTS:
    _IMPRECISE_INTENTS.add(intent.intent)
    _IMPRECISE_COMPONENT_INTENTS.add(intent)


cdef dict GetAttributeMaps():
  """Returns the maps between Intent field values and Intents."""

  return _ATTRIBUTE_MAPS


cdef set GetPreciseIntents():
  """Returns the set of precise Intent objects."""

  return _PRECISE_INTENTS


cdef set GetPreciseComponentIntents():
  """Returns the set of precise ComponentIntent objects."""

  return _PRECISE_COMPONENT_INTENTS


cdef set GetImpreciseComponentIntents():
  """Returns the set of imprecise ComponentIntent objects."""

  return _IMPRECISE_COMPONENT_INTENTS


def Reset():
  """Resets global Intent sets and maps."""

  _PRECISE_INTENTS.clear()
  _IMPRECISE_INTENTS.clear()
  _PRECISE_COMPONENT_INTENTS.clear()
  _IMPRECISE_COMPONENT_INTENTS.clear()

  for key in _ATTRIBUTE_MAPS.iterkeys():
    _ATTRIBUTE_MAPS[key] = {}
