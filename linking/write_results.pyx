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
"""Module to write Intent links to a compressed file."""

cimport cython
cimport numpy as np

import bloscpack
import numpy as np

from linking.intents cimport ComponentIntent
from linking.intents cimport Intent


DTYPE = [('intent', 'int32'),
         ('explicit', 'int8'),
         ('data', 'int8'),
         ('library', 'int8'),
         ('extras', 'int8'),
         ('target', 'int32'),
         ('permission', 'int8'),
         ('probability', 'int8'),
         ('intra_app','int8')]


# This is about one MB.
# The chunk size should be a multiple of 15, since a single row takes 15 bytes.
CHUNK_SIZE = 15 * 70000


@cython.boundscheck(False)
def WriteResults(dict intent_links, int size, str destination):
  """Writes Intent links and probabilities to file.

  Args:
    intent_links: A map between ComponentIntent objects and targets and
    probability values.
    destination: The path to the destination file.
  """

  cdef np.ndarray[Row] results = MakeResultsArray(intent_links, size)
  with open(destination, 'wb') as destination_file:
    bloscpack.pack_ndarray_file(results, destination, chunk_size=CHUNK_SIZE)


@cython.boundscheck(False)
cpdef np.ndarray[Row] MakeResultsArray(dict intent_links, int size):
  """Generates a Numpy array from a map of Intent links.

  Args:
    intent_links: A map between ComponentIntent objects and targets and
    probability values.
    size: The total number of links.

  Returns: The Numpy array of Intent links with attributes.
  """

  cdef np.ndarray[Row] result = np.empty(size, dtype=DTYPE)
  cdef ComponentIntent component_intent
  cdef Intent intent
  cdef tuple targets_and_attributes
  cdef Py_ssize_t index = 0
  cdef list targets
  cdef Py_ssize_t targets_size
  cdef Py_ssize_t new_index
  cdef np.int8_t data
  cdef Py_ssize_t i, j
  for component_intent, targets_and_attributes in intent_links.iteritems():
    intent = component_intent.intent
    targets = targets_and_attributes[0]
    targets_size = len(targets)
    new_index = index + targets_size

    # Using broadcasting throughout.
    result[index:new_index]['intent'] = component_intent.id

    result[index:new_index]['explicit'] = 1 if intent.IsExplicit() else 0

    if not intent.HasData():
      data = 0
    elif intent.HasImpreciseData():
      data = 1
    else:
      data = 2
    result[index:new_index]['data'] = data

    result[index:new_index]['library'] = \
        1 if component_intent.library_exit_point else 0

    result[index:new_index]['extras'] = 0 if intent.extra is None else 1

    result[index:new_index]['probability'] = targets_and_attributes[1]

    for i in xrange(targets_size):
      target = targets[i]
      j = i + index
      result[j].target = target.id
      result[j].permission = 1 if target.permission is not None else 0
      result[j].intra_app = \
          1 if intent.application.name == target.application_id else 0

    index = new_index

  return result
