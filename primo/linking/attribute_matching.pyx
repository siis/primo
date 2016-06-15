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
"""Utilities for matching attributes with end points."""
import re


cdef class AttributeMap(object):
  """Class that maps attributes to end points that contain them."""

  def __cinit__(self):
    self._regexes = {}
    self._constants = {}
    self._all_end_points = set()
    self._end_points_with_regexes = set()
    self._cache = {}

  def __repr__(self):
    return str(self._regexes) + ' - ' + str(self._constants)

  cdef void AddAttribute(self, unicode attribute, object end_point):
    """Adds an attribute and the end point that contains it.

    Args:
      attribute: A field value.
      end_point: The end point that contains the field value.
    """

    if hasattr(attribute, '__iter__') and len(attribute) == 0:
      # We want the empty set to use the None key.
      attribute = None

    cdef dict attribute_map = None
    if (attribute is not None and '(.*)' in attribute):
      attribute_map = self._regexes
      self._end_points_with_regexes.add(end_point)
    else:
      attribute_map = self._constants
    cdef set end_points = attribute_map.get(attribute)
    if not end_points:
      end_points = set()
      attribute_map[attribute] = end_points
    end_points.add(end_point)
    self._all_end_points.add(end_point)

  cdef set GetEndPointsForAttributeSet(
      self, object attribute_set, set search_space=None, bint match_all=True):
    """Returns all end points matching attributes from a set.

    Args:
      attribute_set: An iterable of attributes.
      search_space: The search space.
      match_all: If set to True, then only end points matching all attributes
      are returned. Otherwise, returned end points will match any attribute.

    Returns: All matching end points.
    """

    if not attribute_set:
      return search_space

    cdef list end_point_sets = [self.GetEndPointsForAttribute(attribute, None)
                                for attribute in attribute_set]
    cdef set result = None
    for end_points in end_point_sets:
      if result is not None:
        if match_all:
          result = result & end_points
        else:
          result = result | end_points
      else:
        result = end_points

    if search_space is not None:
      result = result & search_space
    return result

  cdef set GetEndPointsForAttribute(self, unicode attribute,
                                    set search_space=None):
    """Returns the end points that have a certain attribute among a set of end
    points.

    Args:
      attribute: A field value.
      search_space: The search space.

    Returns: All matching end points.
    """

    if attribute == u'(.*)':
      return (self._all_end_points & search_space if search_space is not None
              else self._all_end_points)

    cdef set end_points
    try:
      end_points = self._cache[attribute]
    except KeyError:
      end_points = self._constants.get(attribute, set())
      # Bypass regular expression matching if no end point in the search space
      # is associated with a regex.
      if attribute is not None and '(.*)' in attribute:
        for candidate, end_points_for_attribute in self._constants.iteritems():
          if candidate is not None and NonEmptyIntersection(candidate, attribute):
            end_points = end_points | end_points_for_attribute
      if self._end_points_with_regexes:
        for candidate, end_points_for_attribute in self._regexes.iteritems():
          if attribute is not None and NonEmptyIntersection(candidate, attribute):
            end_points = end_points | end_points_for_attribute
      self._cache[attribute] = end_points

    # Only retain the ones that are in the search space.
    if search_space is not None: end_points = end_points & search_space

    return end_points

  cdef set GetEndPointsWithoutEmptySet(self, set search_space):
    """Selects the end points that have a non-empty set of attributes.

    Args:
      search_space: The search space.

    Returns: All end points that have a non-empty set of attributes.
    """

    cdef set empty_set = self._constants.get(None, set())
    return (search_space - empty_set)

  cdef set GetEndPointsForEmptySet(self, set search_space):
    """Selects the end points with an empty set of attributes.

    Args:
      search_space: The search space.

    Returns: All end points that have a non-empty set of attributes.
    """

    return self.GetEndPointsForAttribute(None, search_space)

  def __str__(self):
    parts = ['%s: %s' % (key, value)
             for (key, value) in self._constants.iteritems()]
    parts += ['%s: %s' % (key, value)
              for (key, value) in self._regexes.iteritems()]
    return '\n'.join(parts)


cdef bint NonEmptyIntersection(unicode regex1, unicode regex2):
  """Determines if the languages described by two regular expressions have a
  non empty intersection.

  Args:
    regex1: A regular expression.
    regex2: Another regular expression.

  Returns: True if the two regular expressions describe languages with non-empty
  intersection.
  """

  #comment this out if you want (.*) and (.*) to not match
  #return regex1==regex2

  if regex1 == u'(.*)':
    # This matches everything.
    return True
  elif regex2 == u'(.*)':
    # This matches everything.
    return True
  elif '(.*)' in regex1:
    # At least one string is a regex.
    if re.match(EscapeRegex(regex1), regex2):
      return True

    if '(.*)' in regex2:
      # We need to consider this case as an attempt to find the intersection of
      # two regular expressions.
      # For example, if regex1 = 'ab.*d' and regex2 = 'a.*d', then this will return
      # True.
      return re.match(EscapeRegex(regex2), regex1)
    return False
  elif '(.*)' in regex2:
    # If we come here, then only regex2 is a regex.
    return re.match(EscapeRegex(regex2), regex1)
  else:
    # Neither is a regex.
    return regex1 == regex2


cdef unicode EscapeRegex(unicode astr):
  """Turns a string into a proper regular expression.

  This involves escaping characters such as . and also not escaping parts of
  strings that are unknown, as indicated by (.*).

  Args:
    astr: A string.

  Returns: The cleansed regular expression.
  """

  return re.escape(astr.replace('(.*)', 'ddddddd')).replace('ddddddd', '.*')
