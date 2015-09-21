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
"""Module for recording field imprecision distribution and for introducing
imprecise fields according to a given distribution."""

from linking.intents cimport Intent

from collections import Counter
import random

include 'linking/constants.pxi'


# Explicit Intent imprecision counters.
cdef object _EXPLICIT_IMPRECISE_COUNTER = Counter()
cdef object _EXPLICIT_PARTIALLY_PRECISE_COUNTER = Counter()
cdef object _EXPLICIT_FIELD_COUNTER = Counter()

# Implicit Intent imprecision counters.
cdef object _IMPLICIT_IMPRECISE_COUNTER = Counter()
cdef object _IMPLICIT_PARTIALLY_PRECISE_COUNTER = Counter()
cdef object _IMPLICIT_FIELD_COUNTER = Counter()

# Empirical Intent imprecision frequencies.
cdef dict _EXPLICIT_IMPRECISE_RATIOS = {}
cdef dict _EXPLICIT_PARTIALLY_PRECISE_RATIOS = {}
cdef dict _IMPLICIT_IMPRECISE_RATIOS = {}
cdef dict _IMPLICIT_PARTIALLY_PRECISE_RATIOS = {}

# Records when a partial imprecision
cdef dict _FORCE_PARTIAL_IMPRECISION = {}


cdef void UpdateImpreciseDistribution(Intent intent):
  """Updates imprecision distribution data with an Intent.

  Args:
    intent: An Intent.
  """

  if intent.IsExplicit():
    for field_name in EXPLICIT_ATTRS:
      field_value = getattr(intent, field_name)
      if field_value is None:
        continue
      _EXPLICIT_FIELD_COUNTER[field_name] += 1
      if field_value == '(.*)':
        _EXPLICIT_IMPRECISE_COUNTER[field_name] += 1
      elif '(.*)' in field_value:
        _EXPLICIT_PARTIALLY_PRECISE_COUNTER[field_name] += 1
  else:
    for field_name in IMPLICIT_ATTRS:
      field_value = getattr(intent, field_name)
      if field_value is None:
        continue
      _IMPLICIT_FIELD_COUNTER[field_name] += 1
      if field_value == '(.*)':
        _IMPLICIT_IMPRECISE_COUNTER[field_name] += 1
      elif '(.*)' in field_value:
        if field_name == 'categories':
          _IMPLICIT_IMPRECISE_COUNTER[field_name] += 1
        else:
          _IMPLICIT_PARTIALLY_PRECISE_COUNTER[field_name] += 1


cdef void MakeRandomImprecision(Intent intent):
  """Generates random imprecisions for a given Intent, following the
  distribution of imprecisions in the real Intent data.

  This method modifies the argument Intent, so it should be used on a copy of
  the original Intent if the original is to be retained as is.

  Args:
    intent: An Intent.
  """

  if not _EXPLICIT_IMPRECISE_RATIOS:
    # Update empirical frequencies.
    for key, count in _EXPLICIT_IMPRECISE_COUNTER.iteritems():
      total = _EXPLICIT_FIELD_COUNTER[key]
      if total == 0:
        _EXPLICIT_IMPRECISE_RATIOS[key] = 0
      else:
        _EXPLICIT_IMPRECISE_RATIOS[key] = float(count) / total
    for key, count in _EXPLICIT_PARTIALLY_PRECISE_COUNTER.iteritems():
      total = _EXPLICIT_FIELD_COUNTER[key]
      if total == 0:
        _EXPLICIT_PARTIALLY_PRECISE_RATIOS[key] = 0
      else:
        _EXPLICIT_PARTIALLY_PRECISE_RATIOS[key] = float(count) / total
    for key, count in _IMPLICIT_IMPRECISE_COUNTER.iteritems():
      total = _IMPLICIT_FIELD_COUNTER[key]
      if total == 0:
        _IMPLICIT_IMPRECISE_RATIOS[key] = 0
      else:
        _IMPLICIT_IMPRECISE_RATIOS[key] = float(count) / total
    for key, count in _IMPLICIT_PARTIALLY_PRECISE_COUNTER.iteritems():
      total = _IMPLICIT_FIELD_COUNTER[key]
      if total == 0:
        _IMPLICIT_PARTIALLY_PRECISE_RATIOS[key] = 0
      else:
        _IMPLICIT_PARTIALLY_PRECISE_RATIOS[key] = float(count) / total

  if intent.IsExplicit():
    for field_name in EXPLICIT_ATTRS:
      try:
        if getattr(intent, field_name) is None:
          continue
        imprecision = IntroduceCompleteImprecision(
            intent, field_name, _EXPLICIT_IMPRECISE_RATIOS[field_name])
      except KeyError:
        # Some field are never imprecise in small data sets.
        imprecision = False
      if not imprecision:
        try:
          IntroducePartialImprecision(
              intent, field_name, _EXPLICIT_PARTIALLY_PRECISE_RATIOS[field_name])
        except KeyError:
          pass
  else:
    for field_name in IMPLICIT_ATTRS:
      if getattr(intent, field_name) is None:
        continue
      try:
        imprecision = IntroduceCompleteImprecision(
            intent, field_name, _IMPLICIT_IMPRECISE_RATIOS[field_name])
      except KeyError:
        imprecision = False
      if not imprecision:
        try:
          IntroducePartialImprecision(
              intent, field_name, _IMPLICIT_PARTIALLY_PRECISE_RATIOS[field_name])
        except KeyError:
          pass


cdef bint IntroduceCompleteImprecision(Intent intent, str field_name,
                                       float bias):
  """Replaces an entire field with .*.

  Args:
    intent: The Intent to be modified.
    field_name: The name of a field.
    bias: The bias indicating the distribution that should be followed.
  """

  if MakeRandomDraw(bias):
    if (field_name == 'categories'):
      setattr(intent, field_name, (u'(.*)',))
    else:
      setattr(intent, field_name, u'(.*)')
    return True
  return False


cdef bint IntroducePartialImprecision(Intent intent, str field_name,
                                      float bias):
  """Replaces part of a field with .*.

  Args:
    intent: The Intent to be modified.
    field_name: The name of a field.
    bias: The bias indicating the distribution that should be followed.
  """

  cdef object field_value
  if _FORCE_PARTIAL_IMPRECISION.get(field_name) and MakeRandomDraw(bias):
    field_value = getattr(intent, field_name)
    if field_value:
      _FORCE_PARTIAL_IMPRECISION[field_name] = False
      setattr(intent, field_name, MakePartialFieldImprecision(field_value))
      return True
    else:
      _FORCE_PARTIAL_IMPRECISION[field_name] = True
      return False
  else:
    return False


cdef bint MakeRandomDraw(float bias):
  """Makes a biased random draw.

  Args:
    bias: A bias between 0 and 1.
  """

  return random.random() < bias


cdef unicode MakePartialFieldImprecision(unicode value):
  """Helper function to introduce a partial field imprecision.

  This randomly determines whether the beginning or the end of the string should
  be replaced and how many characters should be replaced.
  """

  cutoff = random.randint(0, len(value))
  if MakeRandomDraw(0.5):
    # Replace prefix.
    return u'(.*)' + value[:cutoff]
  else:
    # Replace suffix.
    return value[cutoff:] + u'(.*)'
