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
"""Global target field data."""

# Component type preprocessor constants.
DEF RECEIVER = 2
DEF DYNAMIC_RECEIVER = 3

from collections import Counter
import logging

from linking.attribute_matching cimport AttributeMap

from linking.util import Powerset
from linking import ic3_data_pb2


LOGGER = logging.getLogger(__name__)


# Convenience constants.
ACTION = ic3_data_pb2.ACTION
CATEGORY = ic3_data_pb2.CATEGORY
SCHEME = ic3_data_pb2.SCHEME
HOST = ic3_data_pb2.HOST
PORT = ic3_data_pb2.PORT
PATH = ic3_data_pb2.PATH
TYPE = ic3_data_pb2.TYPE
KIND = 'kind'
USED_PERMISSIONS = 'used_permissions'
PACKAGE = 'package'
CLASS = 'class'
BASE_TYPE = 'base_type'
_COUNTER_STRATEGIES = {ACTION: tuple,
                       CATEGORY: Powerset,
                       SCHEME: tuple,
                       HOST: tuple,
                       PORT: tuple,
                       PATH: tuple,
                       TYPE: tuple,
                       KIND: tuple,
                       USED_PERMISSIONS: tuple,
                       PACKAGE: tuple}

# Intent Filter and component constants.
cdef AttributeMap _ACTION_TO_FILTERS = AttributeMap()
cdef AttributeMap _APP_TO_COMPONENTS = AttributeMap()
cdef AttributeMap _APP_TO_APP = AttributeMap()
cdef AttributeMap _APP_TO_FILTERS = AttributeMap()
cdef AttributeMap _COMPONENT_TO_APPS = AttributeMap()
cdef AttributeMap _BASE_TYPE_TO_FILTERS = AttributeMap()
cdef AttributeMap _CATEGORY_TO_FILTERS = AttributeMap()
cdef AttributeMap _COMPONENT_NAME_TO_COMPONENTS = AttributeMap()
cdef tuple _KIND_TO_COMPONENTS = (set(), set(), set(), set(), set())
_EXPORTED_COMPONENTS = set()
_EXPORTED_FILTERS = set()
_NO_DATA_FILTERS = set()
cdef AttributeMap _SCHEME_TO_FILTERS = AttributeMap()
cdef AttributeMap _HOST_TO_FILTERS = AttributeMap()
cdef AttributeMap _PORT_TO_FILTERS = AttributeMap()
cdef AttributeMap _PATH_TO_FILTERS = AttributeMap()
cdef AttributeMap _TYPE_TO_FILTERS = AttributeMap()
cdef tuple _KIND_TO_FILTERS = (set(), set(), set(), set(), set())
cdef AttributeMap _USED_PERMISSION_TO_FILTERS = AttributeMap()
cdef AttributeMap _EXTRA_TO_FILTERS = AttributeMap()
cdef AttributeMap _EXTRA_TO_COMPONENTS = AttributeMap()
_ATTRIBUTE_MAPS = {ACTION: [_ACTION_TO_FILTERS],
                   CATEGORY: [_CATEGORY_TO_FILTERS],
                   SCHEME: [_SCHEME_TO_FILTERS],
                   HOST: [_HOST_TO_FILTERS],
                   PORT: [_PORT_TO_FILTERS],
                   PATH: [_PATH_TO_FILTERS],
                   TYPE: [_TYPE_TO_FILTERS],
                   KIND: [_KIND_TO_COMPONENTS, _KIND_TO_FILTERS],
                   PACKAGE: [_APP_TO_COMPONENTS, _APP_TO_FILTERS],
                   CLASS: [_COMPONENT_NAME_TO_COMPONENTS]}

# Counts the frequency of Intent Filter attribute values.
cdef dict _COUNTERS = {ACTION: Counter(),
                       CATEGORY: Counter(),
                       SCHEME: Counter(),
                       HOST: Counter(),
                       PORT: Counter(),
                       PATH: Counter(),
                       TYPE: Counter(),
                       KIND: Counter(),
                       USED_PERMISSIONS: Counter(),
                       PACKAGE: Counter()}

# Counts the overall number of Intent Filters.
cdef list FILTER_COUNT = [0]

# Map between component kinds and applications that export them.
cdef dict _EXPORTED_APPS = {}


cdef void AddComponent(Component component):
  """Adds a component and updates the appropriate sets and maps.

  Args:
    component: The component to be added.
  """

  cdef unicode name = component.name
  cdef Application app = component.application
  cdef unicode app_name = app.name
  _APP_TO_COMPONENTS.AddAttribute(app_name, component)
  _APP_TO_APP.AddAttribute(app_name, app)
  _COMPONENT_NAME_TO_COMPONENTS.AddAttribute(name, component)
  _COMPONENT_TO_APPS.AddAttribute(name, app)
  FILTER_COUNT[0] += len(component.filters)
  cdef int target_count = len(component.filters) if component.filters else 1
  AddKindToCounter(component.kind, target_count)
  _COUNTERS[PACKAGE][app_name] += target_count
  _KIND_TO_COMPONENTS[component.kind].add(component)
  for intent_filter in component.filters:
    _APP_TO_FILTERS.AddAttribute(app_name, intent_filter)
    _KIND_TO_FILTERS[component.kind].add(intent_filter)
    if app.used_permissions:
      for used_permission in app.used_permissions:
        _COUNTERS[USED_PERMISSIONS][used_permission] += 1
        _USED_PERMISSION_TO_FILTERS.AddAttribute(used_permission,
                                                  intent_filter)
    else:
      _COUNTERS[USED_PERMISSIONS][None] += 1
      _USED_PERMISSION_TO_FILTERS.AddAttribute(None, intent_filter)
    if component.extras:
      for extra in component.extras:
        try:
          _EXTRA_TO_FILTERS.AddAttribute(extra, intent_filter)
        except TypeError:
          _EXTRA_TO_FILTERS.AddAttribute(extra.extra, intent_filter)

  if component.exported:
    _EXPORTED_COMPONENTS.add(component)
    for intent_filter in component.filters:
      _EXPORTED_FILTERS.add(intent_filter)

  if component.extras:
    for extra in component.extras:
      try:
        _EXTRA_TO_COMPONENTS.AddAttribute(extra, component)
      except TypeError:
        _EXTRA_TO_COMPONENTS.AddAttribute(extra.extra, component)


cdef void PrepareForQueries(set applications):
  """Prepares the entry point field data for queries.

  Args:
    applications: The set of applications being studied.
  """

  exported_apps = _EXPORTED_APPS
  exported_apps[ic3_data_pb2.Application.Component.ACTIVITY] = set()
  exported_apps[ic3_data_pb2.Application.Component.SERVICE] = set()
  exported_apps[ic3_data_pb2.Application.Component.RECEIVER] = set()

  for application in applications:
    for kind in exported_apps.iterkeys():
      if application.exported_component_maps[kind]:
        exported_apps[kind].add(application)


cdef int GetExportedComponentCount(int kind, set search_space=None):
  """Returns the number of apps with exported components of a certain kind.

  To be more accurate, we should only return the number of applications with
  components of a certain kind whose name matches a certain regular expression.
  """

  cdef int result
  if search_space is not None:
    result = len(_EXPORTED_APPS[kind] & search_space)
  else:
    result = len(_EXPORTED_APPS[kind])
  return result


cdef set GetAppsMatching(unicode app_name, unicode component_name):
  """Returns all application matching a given name (possibly regex)."""

  return (_APP_TO_APP.GetEndPointsForAttribute(app_name)
          & _COMPONENT_TO_APPS.GetEndPointsForAttribute(component_name))


cdef void AddKindToCounter(int kind, int count=1):
  """Adds components to the kind counter.

  Args:
    kind: A component kind.
    count: The component kind.
  """

  if (kind == ic3_data_pb2.Application.Component.RECEIVER
      or kind == ic3_data_pb2.Application.Component.DYNAMIC_RECEIVER):
    _COUNTERS[KIND][ic3_data_pb2.Application.Component.RECEIVER] += count
  else:
    _COUNTERS[KIND][kind] += count


cdef set GetComponentsWithName(unicode component_name, set search_space):
  """Returns the components with a given name from a set of components.

  Args:
    component_name: A component name.
    search_space: The search space.

  Returns: The set of components with the requested name.
  """

  return _COMPONENT_NAME_TO_COMPONENTS.GetEndPointsForAttribute(
      component_name, search_space)


cdef set GetComponentsOfApp(unicode app_name, set search_space):
  """Returns the components of a given application from a set of components.

  Args:
    app_name: The name of an application.
    search_space: The search space.

  Returns: The set of components of the given application.
  """

  return _APP_TO_COMPONENTS.GetEndPointsForAttribute(app_name, search_space)


cdef long GetTargetCountForValue(object field, object value):
  """Returns the number of target with a given field value.

  Args:
    field: A field name or index.
    value: A field value.

  Returns: The number of targets with the given field value.
  """

  cdef long total
  cdef long current
  cdef AttributeMap attribute_map

  if field == KIND:
    return len(_KIND_TO_COMPONENTS[value])
  else:
    total = 0
    for attribute_map in _ATTRIBUTE_MAPS[field]:
      current = (len(attribute_map.GetEndPointsForAttributeSet(value))
                 if hasattr(value, '__iter__')
                 else len(attribute_map.GetEndPointsForAttribute(value)))
      total += current
    return total


cdef void AddIntentFilterAttributes(IntentFilter intent_filter,
                                    dict attributes):
  """Adds Intent Filter attributes to the Filter data.

  Args:
    intent_filter: An Intent Filter.
    attributes: A map of Intent Filter attributes.
  """

  _AddIntentFilterAttribute(ACTION, attributes, _ACTION_TO_FILTERS,
                            intent_filter)
  _AddIntentFilterAttribute(CATEGORY, attributes, _CATEGORY_TO_FILTERS,
                            intent_filter)
  _AddIntentFilterAttribute(SCHEME, attributes, _SCHEME_TO_FILTERS,
                            intent_filter)
  _AddIntentFilterAttribute(HOST, attributes, _HOST_TO_FILTERS,
                            intent_filter)
  _AddIntentFilterAttribute(PORT, attributes, _PORT_TO_FILTERS,
                            intent_filter)
  _AddIntentFilterAttribute(PATH, attributes, _PATH_TO_FILTERS,
                            intent_filter)
  if not intent_filter.HasData():
    _NO_DATA_FILTERS.add(intent_filter)

  if TYPE in attributes:
    for mime_type in attributes[TYPE]:
      _COUNTERS[TYPE][mime_type] += 1
      type_parts = mime_type.split('/', 1)
      if len(type_parts) == 2:
        _BASE_TYPE_TO_FILTERS.AddAttribute(type_parts[0], intent_filter)
        _TYPE_TO_FILTERS.AddAttribute(mime_type, intent_filter)
      else:
        _BASE_TYPE_TO_FILTERS.AddAttribute(u'(.*)', intent_filter)
        _TYPE_TO_FILTERS.AddAttribute(u'(.*)', intent_filter)
  else:
    _TYPE_TO_FILTERS.AddAttribute(None, intent_filter)

  if ic3_data_pb2.HOST in attributes:
    for host in attributes[ic3_data_pb2.HOST]:
      if host == '*':
        # Possibly empty or other host (see http://stackoverflow.com/a/9569925).
        _HOST_TO_FILTERS.AddAttribute(u'(.*)', intent_filter)
      else:
        _HOST_TO_FILTERS.AddAttribute(host, intent_filter)
  else:
    _HOST_TO_FILTERS.AddAttribute(None, intent_filter)


cdef void _AddIntentFilterAttribute(int kind, dict attributes,
                                    AttributeMap attribute_map,
                                    IntentFilter intent_filter):
  """Adds a single Intent Filter attribute to the Filter data.

  Args:
    kind: The type of attribute.
    attributes: A map between Intent Filter attribute names and values.
    attribute_map: An AttributeMap object for the kind of attribute being
    considered.
    intent_filter: An Intent Filter.
  """

  if kind in attributes:
    for attribute_value in _COUNTER_STRATEGIES[kind](attributes[kind]):
      if not attribute_value:
        # The empty set is part of the powerset.
        _COUNTERS[kind][None] += 1
      else:
        _COUNTERS[kind][attribute_value] += 1
    for value in attributes[kind]:
      attribute_map.AddAttribute(value, intent_filter)
  else:
    _COUNTERS[kind][None] += 1
    attribute_map.AddAttribute(None, intent_filter)


cdef set GetFiltersWithKind(int kind, set search_space):
  """Returns all the Intent Filters protecting a given type of component."""

  return GetTargetsWithKind(kind, search_space, _KIND_TO_FILTERS)


cdef set GetComponentsWithKind(int kind, set search_space):
  """Returns all the components of a given type."""

  return GetTargetsWithKind(kind, search_space, _KIND_TO_COMPONENTS)


cdef set GetTargetsWithKind(int kind, set search_space, tuple attribute_map):
  """Returns all the targets with a given type.

  Args:
    kind: A target kind.
    search_space: The search space.
    attribute_map: A map between target types and targets.
  """

  cdef set result = attribute_map[kind]
  result = result.intersection(search_space)
  cdef set additional
  if kind == RECEIVER:
    additional = attribute_map[DYNAMIC_RECEIVER]
    return result.union(additional.intersection(search_space))
  else:
    return result


cdef set GetFiltersWithUsedPermission(unicode used_permission,
                                      set search_space):
  """Returns all Intent Filters from applications declaring given used
  permissions."""

  return _USED_PERMISSION_TO_FILTERS.GetEndPointsForAttribute(
      used_permission, search_space)


cdef set GetFiltersWithAction(unicode action, set search_space):
  """Returns all Intent Filters with a given action."""

  return _ACTION_TO_FILTERS.GetEndPointsForAttribute(action, search_space)


cdef set GetFiltersWithAnyAction(set search_space):
  """Returns all Intent Filters that declare any action."""

  return _ACTION_TO_FILTERS.GetEndPointsWithoutEmptySet(search_space)


cdef set GetFiltersWithCategories(tuple categories, set search_space):
  """Returns all Intent Filters with given categories."""

  return _CATEGORY_TO_FILTERS.GetEndPointsForAttributeSet(categories,
                                                          search_space)


def GetFiltersWithExtraFromSet(extras, search_space):
  """Returns all Intent Filters of components that access at least one extra
  among a set of extras.

  Args:
    extras: A set of extras.
    search_space: The search space.
  """

  return _EXTRA_TO_FILTERS.GetEndPointsForAttributeSet(
      extras, search_space, False)


def GetComponentsWithExtraFromSet(extras, search_space):
  """Returns all components that access at least one extra among a set of
  extras.

  Args:
    extras: A set of extras.
    search_space: The search space.
  """

  return _EXTRA_TO_COMPONENTS.GetEndPointsForAttributeSet(
      extras, search_space, False)


cdef set GetFiltersWithScheme(unicode scheme, set search_space):
  """Returns all Intent Filters with a given scheme."""

  return _SCHEME_TO_FILTERS.GetEndPointsForAttribute(scheme, search_space)


cdef set GetFiltersWithHost(unicode host, set search_space):
  """Returns all Intent Filters with a given host."""

  return _HOST_TO_FILTERS.GetEndPointsForAttribute(host, search_space)


cdef set GetFiltersWithPort(unicode port, set search_space):
  """Returns all Intent Filters with a given port."""

  return _PORT_TO_FILTERS.GetEndPointsForAttribute(port, search_space)


cdef set GetFiltersWithPath(unicode path, set search_space):
  """Returns all Intent Filters with a given path."""

  return _PATH_TO_FILTERS.GetEndPointsForAttribute(path, search_space)


cdef set GetExportedFilters(set search_space):
  """Returns the exported Intent Filters from a set of Filters.

  Args:
    search_space: The search space.
  """

  return search_space & _EXPORTED_FILTERS


cdef set GetFiltersOfApp(unicode app, set search_space):
  """Returns all Intent Filters of a given application from a set of Filters."""

  return _APP_TO_FILTERS.GetEndPointsForAttribute(app, search_space)


cdef set GetFiltersWithBaseTypes(list base_types, search_space):
  """Returns all Intent Filters declaring a base type from a set of
  possibilities.

  Args:
    base_types: A set of base MIME types.
    search_space: The search space.
  """

  return _BASE_TYPE_TO_FILTERS.GetEndPointsForAttributeSet(
      base_types, search_space, False)


cdef set GetFiltersWithTypes(list mime_types, set search_space):
  """Returns all Intent Filters with a MIME type from a set of possibilities."""

  return _TYPE_TO_FILTERS.GetEndPointsForAttributeSet(
      mime_types, search_space, False)


cdef set GetNoDataFilters(set search_space):
  """Returns all Intent Filters that do not declare data fields."""

  return search_space & _NO_DATA_FILTERS


def GetFiltersWithData(search_space):
  """Selects all Intent Filters that declare a data field."""

  return search_space - _NO_DATA_FILTERS


cdef set GetFiltersWithoutType(set search_space):
  """Selects all Intent Filters that do not declare a type."""

  return _TYPE_TO_FILTERS.GetEndPointsForEmptySet(search_space)


cdef set GetFiltersWithType(set search_space):
  """Selects all Intent Filters that declare a type."""

  return _TYPE_TO_FILTERS.GetEndPointsWithoutEmptySet(search_space)


cdef set GetExportedComponents(set search_space):
  """Selects all exported components."""

  if search_space is not None:
    return _EXPORTED_COMPONENTS & search_space
  return _EXPORTED_COMPONENTS
