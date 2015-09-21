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

from linking.components cimport Component

cdef IntentFilter MakeIntentFilter(object intent_filter_pb,
                                   Component component)

cdef class IntentFilter(object):
  cdef Component component
  cdef readonly frozenset categories
  cdef readonly frozenset actions
  cdef readonly tuple schemes
  cdef readonly tuple types
  cdef readonly tuple hosts
  cdef readonly tuple ports
  cdef readonly tuple paths
  cdef set imprecise_fields
  # A descriptor that is component-agnostic.
  cdef readonly tuple short_descriptor
  # A descriptor that takes the enclosing component into account.
  cdef readonly tuple descriptor
  cdef long _hash
  cdef readonly int id

  cdef bint IsImprecise(self)
  cdef bint IsPrecise(self)
  cdef set _GetImpreciseFields(self)
  cdef bint HasData(self)
