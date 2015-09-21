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
"""Class for finding implicit links."""

DEF DEBUG = False

cimport cython
cimport numpy as np

from linking.target_data import BASE_TYPE
from linking.util import Powerset
import logging
import numpy as np
import time

from linking.intent_data cimport GetAttributeMaps
from linking.intent_data cimport GetPreciseIntents
from linking.target_data cimport GetExportedFilters
from linking.target_data cimport GetFiltersOfApp
from linking.target_data cimport GetFiltersWithUsedPermission
from linking.target_data cimport GetFiltersWithAction
from linking.target_data cimport GetFiltersWithAnyAction
from linking.target_data cimport GetFiltersWithBaseTypes
from linking.target_data cimport GetFiltersWithCategories
from linking.target_data cimport GetFiltersWithHost
from linking.target_data cimport GetFiltersWithKind
from linking.target_data cimport GetFiltersWithPath
from linking.target_data cimport GetFiltersWithPort
from linking.target_data cimport GetFiltersWithScheme
from linking.target_data cimport GetFiltersWithType
from linking.target_data cimport GetFiltersWithTypes
from linking.target_data cimport GetFiltersWithoutType
from linking.target_data cimport GetNoDataFilters
from linking.intent_filters cimport IntentFilter
from linking.intents cimport ComponentIntent
from linking.intents cimport Intent
from linking.attribute_matching cimport NonEmptyIntersection

include 'linking/constants.pxi'


DTYPE = np.int8


LOGGER = logging.getLogger(__name__)


cdef class ImplicitLinkFinder(object):
  def __cinit__(self):
    self._intent_cache = {}
    self._filter_to_intent_matches = {}
    self._cache = {}

  @cython.boundscheck(False)
  cdef tuple FindImplicitLinksForIntent(
      self, ComponentIntent component_intent, set intent_filters,
      bint compute_link_attribute, bint precise_intent=True,
      bint validate=False):
    cdef Intent current_intent = component_intent.intent

    IF DEBUG:
      LOGGER.debug('-----Intent-----')
      LOGGER.debug('%s', current_intent)
      LOGGER.debug('-----End Intent-----')

    # Only select filters that have an action.
    intent_filters = self.ActionTest(current_intent, intent_filters)
    if not intent_filters:
      return None
    IF DEBUG:
      LOGGER.debug("after action %s", len(intent_filters))

    intent_filters = self.CategoryTest(current_intent, intent_filters)
    if not intent_filters:
      return None
    IF DEBUG:
      LOGGER.debug("after category %s", len(intent_filters))

    intent_filters = self.KindTest(current_intent, intent_filters)
    if not intent_filters:
      return None
    IF DEBUG:
      LOGGER.debug("after kind test %s", len(intent_filters))

    intent_filters = self.DataTest(current_intent, intent_filters)
    if not intent_filters:
      return None
    IF DEBUG:
      LOGGER.debug("after data: %s", len(intent_filters))

    cdef IntentFilter filt
    if precise_intent:
      for filt in intent_filters:
        self.AddPreciseIntentMatch(filt.short_descriptor, current_intent)

    intent_filters = self.IntentPermissionTest(current_intent, intent_filters)
    if not intent_filters:
      return None
    IF DEBUG:
      LOGGER.debug("after intent permission %s", len(intent_filters))

    intent_filters = self.VisibilityTest(current_intent, intent_filters)
    if not intent_filters:
      return None
    IF DEBUG:
      LOGGER.debug("after visibility test %s", len(intent_filters))

    intent_filters = self.PackageTest(current_intent, intent_filters)
    if not intent_filters:
      LOGGER.warn('The package %s is listed as destination but is not '
                  'included in our apps.', current_intent.dpackage)
      return None

    cdef list targets = []
    for filt in intent_filters:
      if self.ComponentPermissionTest(current_intent, filt):
        targets.append(filt)

    cdef int targets_size = len(targets)

    if targets_size == 0:
      return None

    cdef DTYPE_t current_link_attribute
    cdef np.ndarray[DTYPE_t, ndim=1] attributes
    cdef Py_ssize_t index = 0

    attribute_computation_time = 0

    if compute_link_attribute:
      start = time.time()
      attributes = np.empty(targets_size, dtype=DTYPE)

      for filt in targets:
        current_link_attribute = self.GetProbabilityForImplicitIntent(
            current_intent, filt, validate)
        attributes[index] = current_link_attribute
        index += 1
      attribute_computation_time = time.time() - start

    return targets, attributes, attribute_computation_time

  cdef set VisibilityTest(self, Intent current_intent, set initial_cut):
    """Performs a visibility test."""

    return (GetExportedFilters(initial_cut)
            | GetFiltersOfApp(current_intent.application_id, initial_cut))

  cdef set DataTest(self, Intent current_intent, set initial_cut):
    """Performs a data test."""

    cdef set cut
    cdef set filters_with_types
    cdef set no_type_filters
    cdef set mime_type_cut
    cdef set no_data_cut
    cdef wildcard_cut
    cdef unicode scheme

    if not current_intent.dtype:
      # Only select Filters with no types.
      no_type_filters = GetFiltersWithoutType(initial_cut)
      if not current_intent.HasData():
        # An intent that contains neither a URI nor a MIME type passes the test
        # only if the filter does not specify any URIs or MIME types.
        cut = GetNoDataFilters(no_type_filters)
      else:
        # An intent that contains a URI but no MIME type (neither explicit nor
        # inferable from the URI) passes the test only if its URI matches the
        # filter's URI format and the filter likewise does not specify a MIME
        # type.
        cut = self.UriDataTest(current_intent, no_type_filters)
    else:
      filters_with_types = GetFiltersWithType(initial_cut)
      mime_type_cut = self.MimeTypeTest(current_intent, filters_with_types)
      if not current_intent.HasData():
        # An intent that contains a MIME type but not a URI passes the test only
        # if the filter lists the same MIME type and does not specify a URI
        # format.
        cut = GetNoDataFilters(mime_type_cut)
      else:
        # An intent that contains both a URI and a MIME type (either explicit or
        # inferable from the URI) passes the MIME type part of the test only if
        # that type matches a type listed in the filter. It passes the URI part
        # of the test either if its URI matches a URI in the filter or if it has
        # a content: or file: URI and the filter does not specify a URI. In
        # other words, a component is presumed to support content: and file:
        # data if its filter lists only a MIME type.
        scheme = current_intent.scheme
        if scheme is not None:
          if scheme == 'content' or scheme == 'file' or scheme == '(.*)':
            no_data_filters = GetNoDataFilters(mime_type_cut)
            wildcard_filters = GetFiltersWithScheme(u'(.*)', mime_type_cut)
            cut = no_data_filters | wildcard_filters
          else:
            cut = self.UriDataTest(current_intent, mime_type_cut)
        else:
          cut = set()

    return cut

  cdef set UriDataTest(self, Intent current_intent, set initial_cut):
    """Performs a URI data test."""

    cdef unicode scheme = current_intent.scheme
    cdef set result
    cdef unicode host
    cdef unicode port
    cdef unicode path

    if scheme is not None:
      result = GetFiltersWithScheme(scheme, initial_cut)
      host = current_intent.host
      if host is not None and host != '(.*)':
        result = GetFiltersWithHost(host, result)
        port = current_intent.port
        if port is not None and port != '(.*)':
          result = GetFiltersWithPort(port, result)
        path = current_intent.path
        if path is not None and path != '(.*)':
          result = GetFiltersWithPath(path, result)
    else:
      result = set()
    return result

  cdef set MimeTypeTest(self, Intent current_intent, set initial_cut):
    """Performs a MIME type test.

    It is assumed that prerequisite checks have already been performed (the
    Intent has a type and the initial cut only contains Filters with types).
    """

    cdef list type_parts = current_intent.dtype.split('/', 1)
    cdef unicode base_type = u'*'
    cdef unicode subtype = u'*'
    if len(type_parts) == 2:
      base_type = type_parts[0]
      subtype = type_parts[1]

    if base_type != '*':
      if subtype != '*':
        return GetFiltersWithTypes([current_intent.dtype,
                                    base_type + u'/*', u'*/*'], initial_cut)
      else:
        return GetFiltersWithBaseTypes([base_type, u'*'], initial_cut)
    else:
      return initial_cut

  cdef set CategoryTest(self, Intent current_intent, set initial_cut):
    """Performs a category test."""

    return (GetFiltersWithCategories(current_intent.categories, initial_cut)
            if current_intent.categories is not None else initial_cut)

  cdef set ActionTest(self, Intent current_intent, set initial_cut):
    """Performs a action test."""

    if current_intent.action:
      initial_cut = GetFiltersWithAction(current_intent.action, initial_cut)
    initial_cut = GetFiltersWithAnyAction(initial_cut)
    return initial_cut

  cdef set IntentPermissionTest(self, current_intent, initial_cut):
    if current_intent.permission:
      return GetFiltersWithUsedPermission(current_intent.permission,
                                          initial_cut)
    else:
      return initial_cut

  cdef set KindTest(self, Intent current_intent, initial_cut):
    """Performs a kind test."""

    return GetFiltersWithKind(current_intent.exit_kind, initial_cut)

  cdef void AddPreciseIntentMatch(self, tuple intent_filter_descriptor, intent):
    cdef set intents
    try:
      intents = self._filter_to_intent_matches[intent_filter_descriptor]
    except KeyError:
      intents = set()
      self._filter_to_intent_matches[intent_filter_descriptor] = intents
    intents.add(intent)

  cdef set PackageTest(self, Intent current_intent, set initial_cut):
    if current_intent.dpackage is not None:
      if current_intent.dpackage != '(.*)':
        return GetFiltersOfApp(current_intent.dpackage, initial_cut)
    return initial_cut

  cdef bint ComponentPermissionTest(self, Intent current_intent,
                                    IntentFilter filt):
    """Performs a component permission test."""

    if filt.permission is not None:
      if current_intent.used_permissions is not None:
        for perm in current_intent.used_permissions:
          if NonEmptyIntersection(filt.permission, perm):
            return True
    else:
      return True
    return False

  cdef set GetIntentMatchesForFilter(self, IntentFilter intent_filter):
    return self._filter_to_intent_matches[intent_filter.short_descriptor]

  @cython.cdivision(True)
  cdef DTYPE_t GetProbabilityForImplicitIntent(
      self, Intent intent, IntentFilter intent_filter, bint validate) except -1:
    """Computes the probability that a link if a true positive.

    If this is called during a validation phase, we do not use the cache, since
    Intent descriptors are not reliable.
    """
    cdef tuple key = (intent, intent_filter)
    cdef DTYPE_t cache_value = (-1 if validate else self._cache.get(key, -1))

    if cache_value >= 0:
      return cache_value

    if intent.IsPrecise():
      if intent_filter.IsPrecise():
        if not validate:
          self._cache[key] = 100
        return 100
      #TODO Handle imprecise Intent Filters.
      else:
        if not validate:
          self._cache[key] = 0
        return 0

    cdef set intents
    cdef set imprecise_fields = intent.imprecise_fields
    cdef set precise_fields = IMPLICIT_ATTRS - imprecise_fields
    cdef int matches
    cdef int total
    cdef DTYPE_t probability
    cdef dict precise_attributes_dict = {}
    cdef tuple precise_attributes
    cdef set precise_intents = GetPreciseIntents()

    if len(precise_fields) > 0:
      for field_type in precise_fields:
        precise_attributes_dict[field_type] = getattr(intent, field_type)

      precise_attributes = tuple(sorted(precise_attributes_dict.items()))
      #TODO Handle imprecise fields.
      intents = self.GetIntentsForPreciseFields(precise_attributes)

      if intents is None:
        LOGGER.warn('No training data for field combination for Intent %s.',
                    str(intent))
        if not validate:
          self._cache[key] = 0
        return 0
      else:
        total = len(intents)
        IF DEBUG:
          print total
        if total == 0:
          LOGGER.warn('No training data for field combination for Intent %s.',
                      str(intent))
          if not validate:
            self._cache[key] = 0
          return 0
        try:
          intents = intents & self.GetIntentMatchesForFilter(intent_filter)
          matches = len(intents)
        except KeyError:
          return 0

        probability = <DTYPE_t> ((100.0 * matches) / total)
        if not validate:
          self._cache[key] = probability
        return probability
    else:
      LOGGER.warn('No precise field.')
      total = len(precise_intents)
      matches = self.GetMatchingIntents(intent_filter, precise_intents,
                                        imprecise_fields)
      probability = <DTYPE_t> ((100.0 * matches) / total)
      if not validate:
        self._cache[key] = probability
      return probability

  cdef set GetIntentsForPreciseFields(self, tuple precise_attributes):
    """Finds Intents that have a set of precise fields.

    Args:
      precise_attributes: A mapping of precise fields to their values.
    Returns:
      The set of all Intents that have the same precise fields if any, None if
      no Intent has the same field values.
    """

    try:
      return self._intent_cache[precise_attributes]
    except KeyError:
      pass

    cdef set intents
    cdef str field_type
    cdef dict attribute_maps = GetAttributeMaps()

    sets = []
    for field_type, field_value in precise_attributes:
      try:
        intents = attribute_maps[field_type][field_value]
      except KeyError:
        self._intent_cache[precise_attributes] = None
        return None
      sets.append(intents)

    cdef int index = 0
    cdef int min_size = len(sets[0])
    for i in range(len(sets)):
      candidate_set = sets[i]
      if len(candidate_set) < min_size:
        index = i
        min_size = len(candidate_set)

    intents = sets[index]
    min_set = intents
    for candidate_set in sets:
      if candidate_set is not min_set:
        intents = intents & candidate_set

    self._intent_cache[precise_attributes] = intents

    return intents

  cdef int GetMatchingIntents(self, IntentFilter intent_filter, intents,
                              imprecise_fields):
    data_test = True
    attribute_maps = GetAttributeMaps()
    empty = set()

    for field_type in imprecise_fields:
      if not intents:
        return 0
      if field_type == 'action':
        action_matches = attribute_maps[field_type].get(None, empty)

        for action in intent_filter.actions:
          action_matches = (action_matches
                            | attribute_maps[field_type].get(action, empty))

        intents = intents & action_matches
      elif field_type == 'categories':
        category_matches = set()
        for categories in Powerset(intent_filter.categories):
          category_matches |= attribute_maps[field_type].get(categories, empty)
        intents = intents & category_matches
      elif (data_test and (field_type == 'dtype' or
                           field_type == 'scheme' or
                           field_type == 'host' or
                           field_type == 'path' or
                           field_type == 'port')):
        data_test = False
        filter_types = intent_filter.types
        if not filter_types:
          # A Filter with no type can only match Intents with no type.
          intents = intents & attribute_maps['dtype'].get(None, empty)

          if not intent_filter.HasData():
            # A Filter with no data and no type can only match Intents with no
            # data and no type.
            intents = intents & attribute_maps['scheme'].get(None, empty)

          else:
            # A Filter with data but no type can only match Intents with
            # compatible data and no type.
            intents = self.ReverseUriDataTest(intent_filter, intents)

        else:
          type_matches = set()
          for filter_type in filter_types:
            type_parts = filter_type.split('/', 1)
            base_type = '*'
            subtype = '*'
            if len(type_parts) == 2:
              base_type = type_parts[0]
              subtype = type_parts[1]
            if base_type != '*':
              if subtype != '*':
                type_matches |= attribute_maps['dtype'].get(filter_type,
                                                                 empty)
                type_matches |= attribute_maps['dtype'].get(base_type + '/*',
                                                                 empty)
                type_matches |= attribute_maps['dtype'].get('*/*', empty)
              else:
                type_matches |= attribute_maps[BASE_TYPE].get(base_type, empty)
                type_matches |= attribute_maps[BASE_TYPE].get('*', empty)
          intents = intents & type_matches

          if not intent_filter.HasData():
            # An Intent Filter that has a MIME type but no data matches Intents
            # with compatible MIME type and either no data, or content: or file:
            # data.
            scheme_to_intents = attribute_maps['scheme']
            intents = intents & (scheme_to_intents.get(None, empty) |
                                 scheme_to_intents.get('content', empty) |
                                 scheme_to_intents.get('file', empty))
          else:
            # An Intent Filter with both a MIME type and data matches Intents
            # with compatible MIME type and data.
            intents = self.ReverseUriDataTest(intent_filter, intents)

    return len(intents)

  cdef set ReverseUriDataTest(self, IntentFilter intent_filter, set intents):
    attribute_maps = GetAttributeMaps()
    schemes = intent_filter.schemes
    empty = set()

    if schemes:
      scheme_matches = set()
      for scheme in schemes:
        scheme_matches |= attribute_maps['scheme'].get(scheme, empty)
      intents = intents & scheme_matches
      hosts = intent_filter.hosts
      if hosts:
        host_matches = set()
        for host in hosts:
          host_matches |= attribute_maps['host'].get(host, empty)
        intents = intents & host_matches
        ports = intent_filter.ports
        if ports:
          port_matches = set()
          for port in ports:
            port_matches |= attribute_maps['port'].get(port, empty)
          intents = intents & port_matches
        paths = intent_filter.paths
        if paths:
          path_matches = set()
          for path in paths:
            path_matches |= attribute_maps['path'].get(path, empty)
          intents = intents & path_matches
    else:
      intents = empty

    return intents

  def Reset(self):
    """Resets global Intent state."""

    self._filter_to_intent_matches.clear()
    self._intent_cache.clear()
    self._cache.clear()
