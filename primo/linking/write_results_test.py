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

"""Tests for result generation module."""

from collections import OrderedDict
import numpy as np
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '..'))

from primo.linking import write_results
from primo.linking.applications import Application
from primo.linking.intents import ComponentIntent
from primo.linking.intents import Intent


class MockTarget(object):
  def __init__(self, _id, permission, application):
    self.id = _id
    self.permission = permission
    self.application_id = application.name


class WriteResultsTest(unittest.TestCase):
  def testMakeResultsArray(self):
    application1 = Application(u'app1', None, 1, None)
    application2 = Application(u'app2', None, 1, None)
    intent1 = Intent(None, None, None, None, u'class1', None, None, None, None,
                     None, 0, None, None, application1)
    component_intent1 = ComponentIntent(intent1, None, None, None, 0, (1,), True,
                                        1)
    target1 = MockTarget(1, None, application2)
    target2 = MockTarget(2, u'permission2', application1)
    intent2 = Intent(None, None, u'action2', None, None, None, None, None, None,
                     None, 0, None, None, application2)
    component_intent2 = ComponentIntent(intent2, None, None, None, 0, (2,), False,
                                        2)
    target3 = MockTarget(3, None, application2)
    target4 = MockTarget(4, u'permission2', application1)
    probabilities1 = np.array([4, 7])
    probabilities2 = np.array([0, 100])

    intent_links = OrderedDict()
    intent_links[component_intent1] = ([target1, target2], probabilities1)
    intent_links[component_intent2] = ([target3, target4], probabilities2)

    expected = np.empty(4, dtype=write_results.DTYPE)

    expected[0][0] = 1
    expected[0][1] = 1
    expected[0][2] = 0
    expected[0][3] = 1
    expected[0][4] = 0
    expected[0][5] = 1
    expected[0][6] = 0
    expected[0][7] = 4
    expected[0][8] = 0

    expected[1][0] = 1
    expected[1][1] = 1
    expected[1][2] = 0
    expected[1][3] = 1
    expected[1][4] = 0
    expected[1][5] = 2
    expected[1][6] = 1
    expected[1][7] = 7
    expected[1][8] = 1

    expected[2][0] = 2
    expected[2][1] = 0
    expected[2][2] = 0
    expected[2][3] = 0
    expected[2][4] = 0
    expected[2][5] = 3
    expected[2][6] = 0
    expected[2][7] = 0
    expected[2][8] = 1

    expected[3][0] = 2
    expected[3][1] = 0
    expected[3][2] = 0
    expected[3][3] = 0
    expected[3][4] = 0
    expected[3][5] = 4
    expected[3][6] = 1
    expected[3][7] = 100
    expected[3][8] = 0

    np.testing.assert_array_equal(write_results.MakeResultsArray(intent_links, 4),
                                  expected)


if __name__ == '__main__':
  unittest.main()
