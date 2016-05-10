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

from primo.linking.applications cimport Application
from primo.linking.components cimport Component

cdef class Intent(object):
  cdef readonly unicode permission
  cdef public tuple categories
  cdef public unicode action
  cdef public unicode dpackage
  cdef public unicode dclass
  cdef public unicode dtype
  cdef public unicode scheme
  cdef public unicode path
  cdef readonly tuple extra
  cdef readonly tuple descriptor
  cdef readonly int exit_kind
  cdef public unicode host
  cdef public unicode port
  cdef Application application
  cdef long _hash
  cdef readonly set imprecise_fields
  cdef bint IsEmpty(self)
  cdef bint IsImprecise(self)
  cpdef bint IsPrecise(self)
  cdef bint HasData(self)
  cdef bint HasImpreciseData(self)
  cpdef bint IsExplicit(self)

cdef class ComponentIntent(object):
  cdef readonly Intent intent
  cdef readonly Component component
  cdef readonly unicode exit_point_name
  cdef readonly unicode exit_point_method
  cdef readonly unsigned int exit_point_instruction
  cdef readonly tuple descriptor
  cdef readonly bint library_exit_point
  cdef int _id
  cdef long _hash
  cdef bint IsEmpty(self)
  cdef bint HasData(self)
  cdef bint IsPrecise(self)
  cdef bint HasInternalDestination(self)

cdef ComponentIntent MakeComponentIntent(object intent_pb, Component component,
                                         object exit_point)
