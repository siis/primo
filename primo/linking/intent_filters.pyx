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
"""Class and factory for Intent Filters."""

from primo.linking.components cimport Component
from primo.linking.target_data cimport AddIntentFilterAttributes

from primo.linking import ic3_data_pb2


_ACTION_MAIN = u'android.intent.action.MAIN'
_ATTRIBUTE_KIND_TO_NAME = {ic3_data_pb2.ACTION: 'actions',
                           ic3_data_pb2.CATEGORY: 'categories',
                           ic3_data_pb2.TYPE: 'types',
                           ic3_data_pb2.SCHEME: 'schemes',
                           ic3_data_pb2.HOST: 'hosts',
                           ic3_data_pb2.PORT: 'ports',
                           ic3_data_pb2.PATH: 'paths'}


cdef int _id = 0


cdef IntentFilter MakeIntentFilter(object intent_filter_pb,
                                   Component component):
  """Factory for Intent Filters.

  Args:
    intent_filter_pb: A protobuf Intent Filter object.
    component: The enclosing component.
  """

  categories = None
  actions = None
  schemes = None
  types = None
  hosts = None
  ports = None
  paths = None

  attributes = {}
  for attribute in intent_filter_pb.attributes:
    kind = attribute.kind
    value = attribute.value
    attributes[kind] = value
    if kind == ic3_data_pb2.ACTION:
      actions = frozenset(value)
    elif kind == ic3_data_pb2.CATEGORY:
      categories = frozenset(value)
    elif kind == ic3_data_pb2.TYPE:
      types = tuple(sorted(value))
    elif kind == ic3_data_pb2.SCHEME:
      schemes = tuple(sorted(value))
    elif kind == ic3_data_pb2.HOST:
      hosts = tuple(sorted(value))
    elif kind == ic3_data_pb2.PORT:
      ports = tuple(sorted(value))
    elif kind == ic3_data_pb2.PATH:
      paths = tuple(sorted(value))

  short_descriptor = (categories, actions, schemes, types, hosts, ports, paths,
                      component.kind)
  descriptor = (short_descriptor, component.descriptor)
  result = IntentFilter(component, categories, actions, schemes, types, hosts,
                        ports, paths, short_descriptor, descriptor, _id)
  AddIntentFilterAttributes(result, attributes)

  global _id
  _id += 1
  return result


cdef class IntentFilter(object):
  """A class the represent an Intent Filter."""

  def __cinit__(self, component, categories, actions, schemes, types, hosts,
                ports, paths, short_descriptor, descriptor, id):
    self.component = component
    self.categories = categories
    self.actions = actions
    self.schemes = schemes
    self.types = types
    self.hosts = hosts
    self.ports = ports
    self.paths = paths
    self.short_descriptor = short_descriptor
    self.descriptor = descriptor
    self._hash = hash(descriptor)
    self.id = id
    self.imprecise_fields = self._GetImpreciseFields()

  cdef bint IsImprecise(self):
    """Determines if the Intent Filter has an imprecise field.

    Returns: True if the Intent Filter is imprecise.
    """

    return bool(self.imprecise_fields)

  cdef bint IsPrecise(self):
    """Determines if the Intent Filter only has precise fields.

    Returns: True if the Intent Filter has no imprecise field.
    """

    return not self.IsImprecise()

  cdef set _GetImpreciseFields(self):
    """Computes the set  of imprecise fields for this Intent Filter.

    Returns: The set of imprecise fields for this Intent Filter.
    """

    cdef set result = set()
    for field_type, field_name in _ATTRIBUTE_KIND_TO_NAME.iteritems():
      field_value = getattr(self, field_name)
      if field_value and '(.*)' in field_value:
        result.add(field_type)

    return result if result else None

  cdef bint HasData(self):
    """Determines if this Intent Filter has non-empty data fields.

    Returns: True if this Intent Filter has a non-empty data field.
    """

    return (self.schemes is not None or self.hosts is not None
            or self.ports is not None or self.paths is not None)

  @property
  def kind(self):
    return self.component.kind

  @property
  def permission(self):
    return self.component.permission

  @property
  def used_permissions(self):
    return self.component.application.used_permissions

  @property
  def extras(self):
    return self.component.extras

  @property
  def application_id(self):
    return self.component.application_id

  def IsMain(self):
    """Determines if this Intent Filter is for an entry point into the
    application.

    Returns: True if this Intent Filter has an ACTION_MAIN action.
    """

    return (self.actions and len(self.actions) >= 1
            and IntentFilter._ACTION_MAIN in self.actions)

  def print_end_point(self):
    print "package",self.component.application_id
    print "categories",self.categories
    print "actions",self.actions
    print "schemes",self.schemes
    print "types",self.types
    print "hosts",self.hosts
    print "ports",self.ports
    print "paths",self.paths
    print "kind",self.component.kind

  def __repr__(self):
    return ('IntentFilter(actions=%r, categories=%r, schemes=%r, types=%r,'
            'hosts=%r, ports=%r, paths=%r, kind=%r' %
            (self.actions, self.categories, self.schemes, self.types,
             self.hosts, self.ports, self.paths, self.component.kind))

  def __hash__(self):
    return self._hash

  def __richcmp__(self, object other, int op):
    if op == 2:
      return (isinstance(other, IntentFilter) and
              self.descriptor == other.descriptor)
    raise NotImplementedError
