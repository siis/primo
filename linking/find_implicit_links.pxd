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

cimport numpy as np
from linking.intent_filters cimport IntentFilter
from linking.intents cimport ComponentIntent
from linking.intents cimport Intent

ctypedef np.int8_t DTYPE_t

cdef class ImplicitLinkFinder(object):
  cdef dict _intent_cache
  # Yields the Intents that match a given Intent Filter.
  cdef dict _filter_to_intent_matches
  # Cache of probability values for Intent-to-Filter links.
  cdef dict _cache

  cdef tuple FindImplicitLinksForIntent(
      self, ComponentIntent component_intent, set intent_filters,
      bint compute_link_attribute, bint precise_intent=?, bint validate=?)
  cdef set VisibilityTest(self, Intent current_intent, set initial_cut)
  cdef set DataTest(self, Intent current_intent, set initial_cut)
  cdef set UriDataTest(self, Intent current_intent, set initial_cut)
  cdef set MimeTypeTest(self, Intent current_intent, set initial_cut)
  cdef set CategoryTest(self, Intent current_intent, set initial_cut)
  cdef set ActionTest(self, Intent current_intent, set initial_cut)
  cdef set IntentPermissionTest(self, current_intent, initial_cut)
  cdef set KindTest(self, Intent current_intent, initial_cut)
  cdef void AddPreciseIntentMatch(self, tuple intent_filter_descriptor, intent)
  cdef set PackageTest(self, Intent current_intent, set initial_cut)
  cdef bint ComponentPermissionTest(self, Intent current_intent,
                                    IntentFilter filt)
  cdef set GetIntentMatchesForFilter(self, IntentFilter intent_filter)
  cdef DTYPE_t GetProbabilityForImplicitIntent(
      self, Intent intent, IntentFilter intent_filter, bint validate) except -1
  cdef set GetIntentsForPreciseFields(self, tuple precise_attributes)
  cdef int GetMatchingIntents(self, IntentFilter intent_filter, intents,
                              imprecise_fields)
  cdef set ReverseUriDataTest(self, IntentFilter intent_filter, set intents)
