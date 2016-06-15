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
"""Validate probabilistic approach using k-fold cross validation and
Goodman-Kruskal's gamma."""

cimport cython
cimport numpy as np

from primo.linking.components cimport GetSkippedFilterCount
from primo.linking.intent_data cimport AddPreciseIntent
from primo.linking.intent_data cimport AddImpreciseIntent
from primo.linking.intent_imprecisions cimport MakeRandomImprecision
from primo.linking.intent_imprecisions cimport UpdateImpreciseDistribution
from primo.linking.intents cimport ComponentIntent

import logging
import numpy as np

import gflags

from primo.linking import intent_data
import primo.linking.find_links


FLAGS = gflags.FLAGS

gflags.DEFINE_string('debugvalidation', None,
                     'Write information about disagreeing pairs to debug file.')

_STEP = 1

LOGGER = logging.getLogger(__name__)


cdef void PerformValidation(list intents, bint skip_empty, set components,
                            set intent_filters, list validation_k):
  """Performs k-fold cross validation.

  Args:
    intents: The set of Intents to be used for validation.
    skip_empty: If True, empty Intents will be skipped.
    components: The set of potential target components.
    intent_filters: The set of potential target Intent Filters.
    validation_k: The list of k values for k-fold cross validation.
  """

  # Isolate precise Intents and extract the distribution of imprecisions.
  cdef precise = set()
  cdef ComponentIntent intent
  cdef dict ground_truth
  for intent in intents:
    if skip_empty and intent.IsEmpty():
      continue
    if intent.IsPrecise():
      precise.add(intent)
    else:
      UpdateImpreciseDistribution(intent.intent)

  # The ground truth contains all links with "full confidence" (priority = 100).
  # Any link not in this set has priority 0.
  ground_truth, _, _, _, _, _, _ = primo.linking.find_links.FindLinksForIntents(
      precise, set(), skip_empty, components, intent_filters, False, False)

  # Store the ground truth targets into a set for efficient lookup.
  for intent, targets in ground_truth.iteritems():
    ground_truth[intent] = set(targets)

  cdef list averages = []
  cdef str k_string
  cdef int k
  cdef list gammas
  cdef int iteration

  cdef list training
  cdef list validation

  cdef list new_validation
  cdef int still_precise

  cdef ComponentIntent intent_copy
  cdef object output

  cdef np.ndarray[np.uint64_t, ndim=2] contingency_table

  cdef np.uint64_t agreeing
  cdef np.uint64_t disagreeing
  cdef float gamma

  cdef int skipped_filter_count = GetSkippedFilterCount()

  with open('k_%s.txt' % '-'.join(validation_k), 'w') as output:
    if FLAGS.debugvalidation is not None:
      debug_file = open(FLAGS.debugvalidation, 'a')
    else:
      debug_file = None
    for k_string in validation_k:
      output.write('Performing validation with k = %s.\n' % k_string)
      k = int(k_string)
      gammas = []
      iteration = 0
      for training, validation in KFoldCrossValidation(precise, k, True):
        output.write('Iteration: %s.\n' % iteration)
        iteration += 1
        Reset()
        for intent in training:
          AddPreciseIntent(intent)

        # This new set will contain imprecise versions of the Intents.
        new_validation = []
        still_precise = 0
        for intent in validation:
          intent_copy = intent.Copy()
          is_intent_precise = True
          while is_intent_precise:
            MakeRandomImprecision(intent_copy.intent)
            intent_copy.intent.UpdateImpreciseFields()
            is_intent_precise = intent_copy.intent.IsPrecise()
          AddImpreciseIntent(intent_copy)
          new_validation.append(intent_copy)
          if intent_copy.intent.IsPrecise():
            still_precise += 1

        validation = new_validation
        intent_links, _, _, _, _, _, _ = primo.linking.find_links.FindLinksForIntents(
            training, validation, skip_empty, components, intent_filters, True,
            True)

        contingency_table = BuildContingencyTable(ground_truth, intent_links,
                                                  debug_file=debug_file)
        agreeing, disagreeing, gamma = CalculateGamma(contingency_table)
        gammas.append((iteration, agreeing, disagreeing, gamma, len(training),
                       len(validation), still_precise, skipped_filter_count,
                       contingency_table))
      output.write('Gammas: ' + '********************\n'.join(
          [IterationString(iteration_data) for iteration_data in gammas]))
      average = np.mean([it[3] for it in gammas])
      output.write('Average gamma: %s.' % str(average))
      averages.append((k, average))
    if debug_file:
      debug_file.close()
    output.write('\n\nK  Average Gamma\n')
    output.write('\n'.join(['%2d %s' % it for it in averages]))
    output.write('\n')


cdef str IterationString(tuple iteration_data):
  """Generates a string from the result of an iteration.

  Args:
    iteration_data: The result of an iteration.

  Returns: A string describing the results.
  """

  return ('Iteration: %s\nAgreeing:%s\nDisagreeing:%s\nGamma: %s\n'
          'Training size: %s\nValidation size: %s\n'
          'Precise Intents in validation set: %s\n'
          'Skipped imprecise Intent Filters: %s\nContingency table: %s\n'
          % iteration_data)


@cython.cdivision(True)
@cython.boundscheck(False)
cpdef np.ndarray[np.uint64_t, ndim=2] BuildContingencyTable(
      dict ground_truth, dict intent_links, float step=_STEP,
      object debug_file=None):
  """Builds a contingency table from link results and the ground truth.

  Args:
    ground_truth: The link ground truth.
    intent_links: The found links.
    step: The step size for the discretized probability interval.
    debug_file: If other than None, a file object where debugging output should
    be written.

  Returns: The resulting contingency table.
  """

  cdef Py_ssize_t columns = int(100 / step)
  cdef np.ndarray[np.uint64_t, ndim=2] contingency_table = np.zeros(
      shape=(2, columns), dtype=np.uint64)
  cdef ComponentIntent intent
  cdef tuple targets_and_attributes
  cdef set ground_truth_targets
  cdef list candidate_targets
  cdef np.ndarray[np.int8_t] candidate_attributes
  cdef int i
  cdef np.int8_t probability
  cdef Py_ssize_t row
  cdef Py_ssize_t column

  for intent, targets_and_attributes in intent_links.iteritems():
    try:
      candidate_targets = targets_and_attributes[0]
      candidate_attributes = targets_and_attributes[1]
      ground_truth_targets = ground_truth[intent]
      for i in xrange(len(candidate_targets)):
        row = 1 if candidate_targets[i] in ground_truth_targets else 0
        column = IndexForProbability(candidate_attributes[i], columns, step)
        contingency_table[row, column] += 1
        if (debug_file is not None and
            ((row == 0 and column == 99) or (row == 1 and column == 0))):
          debug_file.write(str(row) + ', ' + str(column) + '\n')
          debug_file.write((u'%r\n%r\n%r\n%r\n%r\n\n' %
                            (intent.component.application.name, intent.id,
                             intent.intent, candidate_targets[i],
                             candidate_targets[i].id)).encode('utf-8'))
    except KeyError:
      # This occurs when an Intent does not have any targets in the ground
      # truth.
      for i in xrange(candidate_attributes.size):
        probability = candidate_attributes[i]
        column = IndexForProbability(probability, columns, step)
        contingency_table[0, column] += 1
        if debug_file is not None and column == 99:
          debug_file.write('0, 99\n')
          debug_file.write((u'%r\n%r\n%r\n%r\n%r\n%r\n\n' %
                            (intent.component.application.name, intent.id,
                             candidate_attributes.size,
                             len(intent.component.application.components),
                             intent.intent,
                             candidate_targets[i])).encode('utf-8'))

  return contingency_table


cpdef Py_ssize_t IndexForProbability(np.int8_t probability, int columns,
                                     float step):
  return probability if probability != columns else probability - 1

# def IndexForProbability(probability, columns, step):
#   index = int(np.floor(probability / step))
#   return index if index != columns else index -1


cpdef tuple CalculateGamma(np.ndarray[np.uint64_t, ndim=2] contingency_table):
  """Calculates gamma from a contingency table.

  Args:
    contingency_table: The contingency table for the problem.

  Returns: A tuple with the number of agreeing pairs, the number of disagreeing
  pairs and the gamma value.
  """

  cdef Py_ssize_t columns = contingency_table.shape[1]
  cdef np.uint64_t agreeing = 0
  cdef int i, j
  for i in xrange(columns - 1):
    factor = contingency_table[0, i]
    for j in xrange(i + 1, columns):
      agreeing += factor * contingency_table[1, j]

  cdef np.uint64_t disagreeing = 0
  for i in xrange(1, columns):
    factor = contingency_table[0, i]
    for j in xrange(i):
      disagreeing += factor * contingency_table[1, j]

  print agreeing
  print disagreeing
  return (agreeing, disagreeing,
          float(agreeing - disagreeing) / (agreeing + disagreeing))


def KFoldCrossValidation(data, k_value, randomize=False):
  """Generates k (training, validation) pairs from the items in the data set.

  Each pair is a partition of the data, where validation is an iterable
  of size |data| / k. So each training iterable is of length
  (k - 1) * |data| / k.

  Args:
    data: The data set.
    k_value: The k in k-fold cross-validation.
    randomize: If True, the a copy of the data set will be randomly shuffled
    before generating the training and validation sets.

  Yields: A (training set, validation set) pair.
  """

  if randomize:
    from random import shuffle
    data = list(data)
    shuffle(data)
  for k in xrange(k_value):
    training = [x for i, x in enumerate(data) if i % k_value != k]
    validation = [x for i, x in enumerate(data) if i % k_value == k]
    yield training, validation


def Reset():
  """Resets some global data.

  This should be called between iterations of the k-fold cross-validation.
  """

  intent_data.Reset()
