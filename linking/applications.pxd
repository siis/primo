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

cdef class Application(object):
  cdef readonly list components
  cdef readonly unicode name
  cdef readonly tuple used_permissions
  cdef readonly long version
  cdef readonly unicode sample
  cdef readonly list intents
  cdef readonly tuple descriptor
  cdef readonly tuple component_maps
  cdef readonly tuple exported_component_maps
  cdef long _hash
  cdef int CountMatchingComponentsOfKind(self, int kind, unicode name)
  cdef bint HasMatchingExportedComponentsOfKind(self, int kind, unicode name)
