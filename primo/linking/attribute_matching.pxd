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

cdef class AttributeMap(object):
  cdef dict _regexes
  cdef dict _constants
  cdef set _all_end_points
  cdef set _end_points_with_regexes
  cdef dict _cache
  cdef void AddAttribute(self, unicode attribute, object end_point)
  cdef set GetEndPointsForAttributeSet(
      self, object attribute_set, set search_space=?, bint match_all=?)
  cdef set GetEndPointsForAttribute(self, unicode attribute, set search_space=?)
  cdef set GetEndPointsWithoutEmptySet(self, set search_space)
  cdef set GetEndPointsForEmptySet(self, set search_space)

cdef bint NonEmptyIntersection(unicode regex1, unicode regex2)
