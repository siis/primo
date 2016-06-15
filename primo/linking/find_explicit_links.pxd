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
from primo.linking.components cimport Component
from primo.linking.intents cimport Intent

ctypedef np.int8_t DTYPE_t

cdef class ExplicitLinkFinder(object):
  cdef int _intra_app
  cdef int _inter_app
  cdef float _probability_intra_app
  cdef float _probability_inter_app
  cdef tuple _CACHE

  cdef void IncrementIntraApp(self)
  cdef void IncrementInterApp(self)
  cdef float GetInterAppProbability(self)
  cdef float GetIntraAppProbability(self)
  cdef tuple FindExplicitLinksForIntent(
      self, Intent current_intent, set components, bint compute_link_attribute,
      bint validate)
  cdef set ExplicitKindTest(self, Intent intent, set initial_cut)
  cdef set ExplicitVisibilityTest(self, Intent intent, set initial_cut)
  cdef DTYPE_t GetProbabilityForExplicitIntent(self, Intent intent,
                                               Component target)
