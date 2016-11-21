#!/usr/bin/python
#
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

"""Tests for validation module."""

import numpy
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '..'))

import linking.validation as validation


class MockAttribute(object):
  def __init__(self, probability):
    self.probability = probability


class ValidationTest(unittest.TestCase):
  def testIndexForProbabilityWithIndexLessThanColumnCount(self):
    self.assertEqual(validation.IndexForProbability(0, 10, 0.1), 0)
    self.assertEqual(validation.IndexForProbability(0.51, 10, 0.1), 5)

  def testIndexForProbabilityWithIndexEqualToColumnCount(self):
    self.assertEqual(validation.IndexForProbability(1, 10, 0.1), 9)

  def testBuildContingencyTableWithKeyError(self):
    intent_links = {'Intent 1': (['Filter 1', 'Filter 2'],
                                 (20, 30)),
                    'Intent 2': (['Filter 3', 'Filter 4'],
                                 (60, 80))}
    ground_truth = {'Intent 2': ['Filter 3', 'Filter 4']}
    wanted_table = numpy.array([[1, 1, 0, 0], [0, 0, 1, 1]])
    numpy.testing.assert_array_equal(
        validation.BuildContingencyTable(ground_truth, intent_links, 25),
        wanted_table)

  def testBuildContingencyTableWithoutKeyError(self):
    intent_links = {'Intent 1': (['Filter 1', 'Filter 2'],
                                 (20, 30)),
                    'Intent 2': (['Filter 3', 'Filter 4'],
                                 (60, 80))}
    ground_truth = {'Intent 1': ['Filter 1'],
                    'Intent 2': ['Filter 4']}
    wanted_table = numpy.array([[0, 1, 1, 0], [1, 0, 0, 1]])
    numpy.testing.assert_array_equal(
        validation.BuildContingencyTable(ground_truth, intent_links, 25),
        wanted_table)

  def testCalculateGamma(self):
    self.assertEqual(validation.CalculateGamma(numpy.array([[1, 1, 0, 0],
                                                            [0, 0, 1, 1]])),
                     1)
    self.assertEqual(validation.CalculateGamma(numpy.array([[0, 0, 1, 1],
                                                            [1, 1, 0, 0]])),
                     -1)
    self.assertEqual(validation.CalculateGamma(numpy.array([[0, 1, 1, 0],
                                                            [1, 0, 0, 1]])),
                     0)
    self.assertEqual(validation.CalculateGamma(numpy.array([[1, 1, 0, 1],
                                                            [0, 0, 1, 0]])),
                     1.0 / 3)


if __name__ == '__main__':
  unittest.main()
