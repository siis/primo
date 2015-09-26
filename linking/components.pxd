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

from linking.applications cimport Application

cdef int GetSkippedFilterCount()
cdef Component MakeComponent(object component_pb, Application application,
                             bint validate)

cdef class Component(object):
  cdef readonly unicode name
  cdef readonly int kind
  cdef readonly unicode permission
  cdef readonly tuple extras
  cdef readonly bint exported
  cdef readonly int exit_point_count
  cdef readonly Application application
  cdef public unicode _filters_attributes_string
  cdef public unicode _intents_attributes_string
  cdef readonly list intents
  cdef readonly tuple descriptor
  cdef readonly list filters
  cdef long _hash
  cdef readonly int id
  cdef bint IsOpenComponent(self)
