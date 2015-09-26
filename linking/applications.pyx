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
"""Application class and factory."""
from linking.components cimport Component
from linking.components cimport MakeComponent
from linking.intents cimport ComponentIntent
from linking.attribute_matching cimport AttributeMap

from linking import ic3_data_pb2


cdef set SAMPLES = set()


def MakeApplication(application_pb, validate):
  """Generates an Application object from a protobuf.

  Args:
    application_pb: An Application protobuf object.

  Returns: A linking.Application object.
  """

  cdef unicode name = application_pb.name
  # In protobufs, fields of type RepeatedScalarFieldContainer (such as
  # used_permissions) contain a weak reference to
  # google.protobuf.internal.python_message._Listener. To avoid pickling
  # issues, we copy the contents.
  cdef tuple used_permissions = (tuple(sorted(application_pb.used_permissions))
                                 if application_pb.used_permissions else None)
  cdef long version = application_pb.version
  cdef unicode sample = (application_pb.sample
                         if application_pb.HasField('sample') else None)

  SAMPLES.add(sample)

  cdef Application application = Application(name, used_permissions, version,
                                             sample)
  cdef list components = []
  for pb_component in application_pb.components:
    components.append(MakeComponent(pb_component, application, validate))
  application.components = components

  cdef tuple component_maps
  cdef tuple exported_component_maps
  # This is relying on the fact that:
  # ic3_data_pb2.Application.Component.ACTIVITY = 0
  # ic3_data_pb2.Application.Component.SERVICE = 1
  # ic3_data_pb2.Application.Component.RECEIVER = 2
  # TODO Check C arrays.
  component_maps = (AttributeMap(), AttributeMap(), AttributeMap())
  exported_component_maps = (AttributeMap(), AttributeMap(), AttributeMap())
  cdef unicode component_name
  cdef int kind
  cdef AttributeMap current_attribute_map
  cdef Component component

  cdef list intents = []
  cdef list component_intents

  for component in components:
    kind = component.kind
    if kind == ic3_data_pb2.Application.Component.PROVIDER:
      continue
    elif kind == ic3_data_pb2.Application.Component.DYNAMIC_RECEIVER:
      kind = ic3_data_pb2.Application.Component.RECEIVER
    component_name = component.name
    current_attribute_map = component_maps[kind]
    current_attribute_map.AddAttribute(component_name, component)
    if component.exported:
      current_attribute_map = exported_component_maps[kind]
      current_attribute_map.AddAttribute(component_name, component)

    component_intents = component.intents
    if component_intents:
      intents += component_intents

  application.component_maps = component_maps
  application.exported_component_maps = exported_component_maps
  application.intents = intents

  return application


cdef class Application(object):
  """A class that represents an application."""

  def __cinit__(self, unicode name, tuple used_permissions, long version,
                unicode sample):
    self.name = name
    self.used_permissions = used_permissions
    self.version = version
    self.sample = sample
    self.descriptor = (self.name, self.version)
    self._hash = hash(self.descriptor)

  cdef int CountMatchingComponentsOfKind(self, int kind, unicode value):
    """Counts the number of components in this application matching a given
    field value.

    Args:
      kind: A field name.
      value: A field value.

    Returns: The number of components matching the field value.
    """

    cdef AttributeMap attribute_map = self.component_maps[kind]
    return len(attribute_map.GetEndPointsForAttribute(value))

  cdef bint HasMatchingExportedComponentsOfKind(self, int kind, unicode value):
    """Determines if any component in this application matches a given field
    value.

    Args:
      kind: A field name.
      value: A field value.

    Returns: True if a component in this application matches the field value.
    """

    return self.CountMatchingComponentsOfKind(kind, value) > 0

  def HasOpenComponent(self):
    """Determines if this application has any component that is publicly
    accessible.

    Returns: True if this application has a component that is publicly
    accessible.
    """

    cdef Component component
    for component in self.components:
      if component.IsOpenComponent():
        return True
    return False

  def SendsExternalIntent(self):
    """Determines if this application sends an Intent to another application.

    Note that this does not take into account potentially imprecise Intents.

    Returns: True if this application sends an Intent to another application.
    """

    cdef ComponentIntent intent
    if self.intents:
      for intent in self.intents:
        if not intent.HasInternalDestination():
          return True
    return False

  property exit_point_count:
    def __get__(self):
      cdef int count = 0
      cdef Component component
      for component in self.components:
        count += component.exit_point_count
      return count

  property intent_count:
    def __get__(self):
      return len(self.intents)

  property intent_filter_count:
    def __get__(self):
      cdef int count = 0
      cdef Component component

      for component in self.components:
        count += component.intent_filter_count
      return count

  def __hash__(self):
    return self._hash

  def __richcmp__(self, object other, int op):
    if op == 2:
      return (isinstance(other, Application)
              and self.descriptor == other.descriptor)
    raise NotImplementedError
