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
"""Some utility functions."""

def PowersetList(initial_set):
  """Computes the power set of a given set.

  If the input is null, it returns the empty set.
  """

  # The power set of the empty set has one element, the empty set.
  result = [[]]
  if initial_set:
    for x in initial_set:
      result.extend([subset + [x] for subset in result])
  return result


def Powerset(initial_set):
  return frozenset([frozenset(elt) for elt in PowersetList(initial_set)])
