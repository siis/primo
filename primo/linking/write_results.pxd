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

cdef packed struct Row:
  np.int32_t intent     # 0
  np.int8_t explicit    # 1
  np.int8_t data        # 2
  np.int8_t library     # 3
  np.int8_t extras      # 4
  np.int32_t target     # 5
  np.int8_t permission  # 6
  np.int8_t probability # 7
  np.int8_t intra_app   # 8

cpdef np.ndarray[Row] MakeResultsArray(dict intent_links, int size)
