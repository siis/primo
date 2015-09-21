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
"""Class and factory for Intent."""

from linking.applications cimport Application
from linking.components cimport Component
from linking.intent_data cimport AddImpreciseIntent
from linking.intent_data cimport AddPreciseIntent
from linking.target_data cimport GetTargetCountForValue

from collections import Counter

from linking import ic3_data_pb2
from linking.target_data import CLASS
from linking.target_data import KIND
from linking.target_data import PACKAGE
from linking.target_data import USED_PERMISSIONS

include 'linking/constants.pxi'


cdef dict _INTENT_COUNTERS = {ic3_data_pb2.ACTION: Counter(),
                              ic3_data_pb2.CATEGORY: Counter(),
                              ic3_data_pb2.SCHEME: Counter(),
                              ic3_data_pb2.HOST: Counter(),
                              ic3_data_pb2.PORT: Counter(),
                              ic3_data_pb2.PATH: Counter(),
                              ic3_data_pb2.TYPE: Counter(),
                              KIND: Counter(),
                              USED_PERMISSIONS: Counter(),
                              PACKAGE: Counter(),
                              CLASS: Counter()}


CATEGORY_DEFAULT = u'android.intent.category.DEFAULT'

cdef int _id = 0


cdef ComponentIntent MakeComponentIntent(object intent_pb, Component component,
                                         object exit_point):
  """Factory for ComponentIntent objects.

  Args:
    intent_pb: A protobuf Intent object.
    component: The component sending the Intent.
    exit_point: The exit point sending the Intent.
  """

  cdef Intent intent = _MakeIntent(intent_pb, component, exit_point, True)
  cdef unicode exit_point_name = exit_point.instruction.class_name
  cdef unicode exit_point_method = exit_point.instruction.method
  cdef unsigned int exit_point_instruction = exit_point.instruction.id

  cdef bint library_exit_point = False

  cdef tuple descriptor = (component.descriptor, exit_point_name,
                           exit_point_method, exit_point_instruction,
                           intent.descriptor)

  global _id
  _id += 1
  cdef ComponentIntent result = ComponentIntent(
      intent, component, exit_point_name, exit_point_method,
      exit_point_instruction, descriptor, library_exit_point, _id)
  if intent.IsPrecise():
    AddPreciseIntent(result)
  else:
    AddImpreciseIntent(result)
  return result


cdef float Expectation(list data):
  cdef float result = 0.0
  cdef float probability
  cdef long value
  for probability, value in data:
    result += probability * value
  return result


def CalculateIntentExpectation():
  """Calculates the expected number of matching targets for individual fields.

  Returns: The expected number of matches for the action and target class
  fields (the most selective for implicit and explicit Intents, respectively).
  """

  print '*****Expectations*****'
  action_expectation = None
  class_expectation = None

  for field, counter in _INTENT_COUNTERS.iteritems():
    value_sum = sum(counter.values())
    data = []
    for field_value, count in counter.iteritems():
      try:
        data.append((float(count) / value_sum,
                     GetTargetCountForValue(field, field_value)))
      except KeyError:
        pass
    expectation = Expectation(data)
    if field == ic3_data_pb2.ACTION:
      action_expectation = expectation
    elif field == CLASS:
      class_expectation = expectation
    try:
      field = ic3_data_pb2.AttributeKind.Name(field)
    except TypeError:
      pass

    print ' '.join((field, str(expectation)))
  return [action_expectation, class_expectation]


cdef class Intent(object):
  """Class representing an Intent, not taking into account the enclosing
  component."""

  def __cinit__(self, permission, categories, action, dpackage, dclass, dtype,
                scheme, path, extra, descriptor, exit_kind, host, port,
                application):
    self.permission = permission
    self.categories = categories
    self.action = action
    self.dpackage = dpackage
    self.dclass = dclass
    self.dtype = dtype
    self.scheme = scheme
    self.path = path
    self.extra = extra
    self.descriptor = descriptor
    self.exit_kind = exit_kind
    self.host = host
    self.port = port
    self.application = application
    self._hash = hash(descriptor)
    self.imprecise_fields = None
    self.UpdateImpreciseFields()

  def Copy(self):
    """Creates a copy of this Intent.

    Returns: A copy of this Intent.
    """

    return Intent(self.permission, self.categories, self.action, self.dpackage,
                  self.dclass, self.dtype, self.scheme, self.path, self.extra,
                  self.descriptor, self.exit_kind, self.host, self.port,
                  self.application)

  def UpdateImpreciseFields(self):
    """Updates the list of imprecise fields.

    This method modifies field self.imprecise_fields and does not return
    anything.
    """

    result = set()
    field_set = EXPLICIT_ATTRS if self.IsExplicit() else IMPLICIT_ATTRS
    for field_name in field_set:
      field_value = getattr(self, field_name)
      if field_value is not None and '(.*)' in field_value:
        result.add(field_name)

    self.imprecise_fields = result if result else None

  cdef bint IsEmpty(self):
    """Determines if none of the fields of this Intent are set.

    Returns: True if none of the field of this Intent are set.
    """

    return (not self.HasData() and self.dpackage is None and
            self.dclass is None and self.action is None and
            (self.categories is None or
             (len(self.categories) == 1 and
              self.categories[0] == CATEGORY_DEFAULT)) and self.dtype is None)

  cdef bint HasData(self):
    """Determines if any of the data fields of this Intent are set.

    Returns: True if at least one of the data fields of the Intent is set.
    """

    return (self.scheme is not None or self.host is not None
            or self.port is not None or self.path is not None)

  cdef bint HasImpreciseData(self):
    """Determines if any data field is imprecise.

    Returns: True if this Intent has any imprecise field.
    """

    return (self.scheme == '(.*)' or self.host == '(.*)' or self.host == '(.*)'
            or self.path == '(.*)')

  cpdef bint IsExplicit(self):
    """Determines if the Intent is explicit."""

    return self.dclass is not None

  cdef bint IsImprecise(self):
    """Determines if the Intent has any imprecise fields."""

    return bool(self.imprecise_fields)

  cpdef bint IsPrecise(self):
    """Determines if the Intent only has precise fields."""
    return not self.IsImprecise()

  property application_id:
    def __get__(self):
      return self.application.name

  property application_components:
    def __get__(self):
      return self.application.components

  property used_permissions:
    def __get__(self):
      return self.application.used_permissions

  def __hash__(self):
    return self._hash

  def __richcmp__(self, other, op):
    if op == 2:
      return (isinstance(other, Intent) and self.descriptor == other.descriptor)
    raise NotImplementedError

  def __str__(self):
    return self.__repr__()

  def __repr__(self):
    return ('Intent(dclass=%r, dpackage=%r, dtype=%r, action=%r, '
            'categories=%r, scheme=%r, path=%r, host=%r, port=%r, kind=%r)' %
            (self.dclass, self.dpackage, self.dtype, self.action,
             self.categories, self.scheme, self.path, self.host, self.port,
             self.exit_kind))


cdef Intent _MakeIntent(object intent_pb, Component component,
                        object exit_point, bint update_counters):
  """Factory for an Intent object.

  Args:
    intent_pb: A protobuf Intent object.
    component: The component sending the Intent.
    exit_point: The exit point sending the Intent.
    update_counters: Flag to indicate whether field value counters should be
    updated.

  Returns: The newly-created Intent object.
  """

  cdef unicode permission = (intent_pb.permission
                             if intent_pb.HasField('permission') else None)
  cdef list categories = []
  cdef unicode action = None
  cdef unicode dpackage = None
  cdef unicode dclass = None
  cdef unicode dtype = None
  cdef unicode uri = None
  cdef unicode scheme = None
  cdef unicode authority = None
  cdef unicode path = None
  cdef list extras = []
  cdef char exit_kind = exit_point.kind
  cdef unicode host = None
  cdef unicode port = None
  cdef Application application = component.application

  if exit_kind == ic3_data_pb2.Application.Component.ACTIVITY:
    categories = [CATEGORY_DEFAULT]
  for attribute in intent_pb.attributes:
    kind = attribute.kind
    value = attribute.value
    if kind == ic3_data_pb2.ACTION:
      action = value[0]
    elif kind == ic3_data_pb2.CATEGORY:
      categories.extend(value)
    elif kind == ic3_data_pb2.PACKAGE:
      dpackage = value[0].replace('/', '.')
      if update_counters:
        _INTENT_COUNTERS[PACKAGE][dpackage] += 1
    elif kind == ic3_data_pb2.CLASS:
      dclass = value[0].replace("/", ".")
      if update_counters:
        _INTENT_COUNTERS[CLASS][dclass] += 1
    elif kind == ic3_data_pb2.TYPE:
      dtype = value[0]
    elif kind == ic3_data_pb2.URI:
      uri = value[0]
    elif kind == ic3_data_pb2.SCHEME:
      scheme = value[0]
    elif kind == ic3_data_pb2.AUTHORITY:
      authority = value[0]
    elif kind == ic3_data_pb2.PATH:
      path = value[0]
    elif kind == ic3_data_pb2.EXTRA:
      extras.extend(value)

  scheme, host, port, path = _ParseUri(uri, authority, scheme, host, port, path)

  cdef tuple categories_tuple = (tuple(sorted(categories)) if categories
                                 else None)

  if update_counters:
    _INTENT_COUNTERS[KIND][exit_kind] += 1
    _INTENT_COUNTERS[ic3_data_pb2.ACTION][action] += 1
    _INTENT_COUNTERS[ic3_data_pb2.CATEGORY][categories_tuple] += 1
    _INTENT_COUNTERS[ic3_data_pb2.SCHEME][scheme] += 1
    _INTENT_COUNTERS[ic3_data_pb2.HOST][host] += 1
    _INTENT_COUNTERS[ic3_data_pb2.PORT][port] += 1
    _INTENT_COUNTERS[ic3_data_pb2.PATH][path] += 1
    _INTENT_COUNTERS[ic3_data_pb2.TYPE][type] += 1

  cdef extras_tuple = tuple(sorted(extras)) if extras else None
  descriptor = (action, categories_tuple, dtype, dpackage, scheme, host, port,
                path, dclass, permission, exit_kind, extras_tuple)

  return Intent(permission, categories_tuple, action, dpackage, dclass, dtype,
                scheme, path, extras_tuple, descriptor, exit_kind, host, port,
                application)

cdef tuple _ParseUri(unicode uri, unicode authority, unicode scheme,
                     unicode host, unicode port, unicode path):
  """Parses a URI."""

  if not uri:
    host, port = _ParseAuthority(authority, port)
    return scheme, host, port, path
  elif uri == '(.*)':
    return u'(.*)', u'(.*)', u'(.*)', u'(.*)'
  else:
    remainder = uri
    uri_parts = remainder.split(':', 1)
    if len(uri_parts) == 2:
      scheme = uri_parts[0]
      remainder = uri_parts[1]
      if remainder == '(.*)':
        host = u'(.*)'
        port = u'(.*)'
        path = u'(.*)'
        return scheme, host, port, path
      if len(remainder) >= 2 and remainder.startswith('//'):
        # This is a hierarchical URI.
        remainder = remainder[2:]
        slash_pos = remainder.find('/')
        authority = remainder[:slash_pos]
        host, port = _ParseAuthority(authority, port)
        remainder = remainder[slash_pos:]
        path = remainder.split('?', 1)[0]
    return scheme, host, port, path


cdef tuple _ParseAuthority(unicode authority, unicode port):
  """Parses the authority part of a URI."""

  if authority is None:
    return None, None
  if authority == '(.*)':
    return u'(.*)', u'(.*)'

  host_and_port_parts = authority.split('@', 1)
  host_and_port = (host_and_port_parts[1] if len(host_and_port_parts) > 1
                   else host_and_port_parts[0])
  host_and_port = host_and_port.split(':', 1)
  host = host_and_port[0]
  if len(host_and_port) == 2:
    port = host_and_port[1]
  return host, port


cdef class ComponentIntent(object):
  """Class for an Intent with information about the sending component."""

  def __cinit__(self, Intent intent, Component component,
                unicode exit_point_name, unicode exit_point_method,
                unsigned int exit_point_instruction, tuple descriptor,
                bint library_exit_point, int _id):
    self.intent = intent
    self.component = component
    self.exit_point_name = exit_point_name
    self.exit_point_method = exit_point_method
    self.exit_point_instruction = exit_point_instruction
    self.descriptor = descriptor
    self.library_exit_point = library_exit_point
    self._id = _id
    self._hash = hash(descriptor)

  def Copy(self):
    """Creates a copy of this ComponentIntent object.

    Returns: The copy of this ComponentIntent object.
    """

    return ComponentIntent(self.intent.Copy(), self.component,
                           self.exit_point_name, self.exit_point_method,
                           self.exit_point_instruction, self.descriptor,
                           self.library_exit_point, self._id)

  cdef bint IsEmpty(self):
    """Determines if this Intent has no field set.

    Returns: True if this Intent is empty.
    """

    return self.intent.IsEmpty()

  cdef bint HasData(self):
    """Determines if any data field of the Intent is set.

    Returns: True if this Intent has any data field set.
    """

    return self.intent.HasData()

  cdef bint HasInternalDestination(self):
    """Determines if this Intent is explicit and has a destination that is
    within the same application."""

    return (self.intent.IsExplicit() and
            self.intent.dpackage == self.intent.application_id)

  cdef bint IsPrecise(self):
    """Determines if this Intent only has precise fields.

    Returns: True if this Intent has no imprecise fields.
    """

    return self.intent.IsPrecise()

  property id:
    def __get__(self):
      return self._id

  def __hash__(self):
    return self._hash

  def __richcmp__(self, other, op):
    if op == 2:
      return (isinstance(other, ComponentIntent) and
              self.descriptor == other.descriptor)
    raise NotImplementedError

  def __repr__(self):
    return ('ComponentIntent(%r, %r, %r, %r, %r, %r)' %
            (self.intent, self.exit_point_name, self.exit_point_method,
             self.exit_point_instruction, self.component, self._id))
