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
"""A class and factory for Android application components."""

import gflags

from linking.applications cimport Application
from linking.target_data cimport AddComponent
from linking.intent_filters cimport IntentFilter
from linking.intent_filters cimport MakeIntentFilter
from linking.intents cimport MakeComponentIntent


FLAGS = gflags.FLAGS


cdef int _id = 0
cdef int _skipped_imprecise_filters = 0


cdef Component MakeComponent(object component_pb, Application application):
  """Generates a Component object from a protobuf.

  Args:
    component_pb: A Component protobuf object.
    application: An Application object.

  Returns: A linking.Component object.
  """

  cdef unicode name = component_pb.name
  cdef int kind = component_pb.kind
  cdef unicode permission = (component_pb.permission
                             if component_pb.HasField('permission') else None)
  cdef tuple extras = tuple(sorted(component_pb.extras))
  cdef bint exported = component_pb.exported
  cdef int exit_point_count = len(component_pb.exit_points)
  cdef set intents = set()
  cdef list filters = []
  cdef IntentFilter intent_filter

  global _id

  cdef Component result = Component(name, kind, permission, extras, exported,
                                    exit_point_count, application, filters, _id)

  _id += 1
  for exit_point in component_pb.exit_points:
    for intent in exit_point.intents:
      component_intent = MakeComponentIntent(intent, result, exit_point)
      intents.add(component_intent)

  result.intents = list(intents)

  for intent_filter_pb in component_pb.intent_filters:
    intent_filter = MakeIntentFilter(intent_filter_pb, result)
    if intent_filter.IsPrecise() or not FLAGS.validate:
      filters.append(intent_filter)
    else:
      global _skipped_imprecise_filters
      _skipped_imprecise_filters += 1

  AddComponent(result)
  return result


cdef int GetSkippedFilterCount():
  return _skipped_imprecise_filters


cdef class Component(object):
  """A class that represents an application component."""

  def __cinit__(self, unicode name, int kind, unicode permission, tuple extras,
                bint exported, int exit_point_count, Application application,
                list filters, int _id):
    self.name = name
    self.kind = kind
    self.permission = permission
    self.extras = extras
    self.exported = exported
    self.exit_point_count = exit_point_count
    self.application = application
    self.descriptor = (application.descriptor, self.name)
    self._hash = hash(self.descriptor)
    self.filters = filters
    self.id = _id

  property intent_count:
    def __get__(self):
      return len(self.intents)

  property intent_filter_count:
    def __get__(self):
      return len(self.filters)

  cdef bint IsOpenComponent(self):
    """Determines if a component is open to other applications.

    Returns:
      True if the component is open to other applications."""

    if not self.exported:
      return False
    for intent_filter in self.filters:
      # We say that the main activity is not open to other applications
      # because starting this component is simply starting the application.
      if not intent_filter.IsMain():
        return True
    return False

  @property
  def application_id(self):
    return self.application.name

  def __hash__(self):
    return self._hash

  def __richcmp__(self, object other, int op):
    if op == 2:
      return (isinstance(other, Component) and
              self.descriptor == other.descriptor)
    raise NotImplementedError

  def __repr__(self):
    return 'Component(%r, %r)' % (self.name, self.application.name)
