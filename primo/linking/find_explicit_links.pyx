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
"""Module for finding an explicit link between an Intent and a component."""
DEF DEBUG = False

cimport cython
cimport numpy as np

import logging
import numpy as np
import time

from primo.linking.applications cimport Application
from primo.linking.components cimport Component
from primo.linking.target_data cimport GetAppsMatching
from primo.linking.target_data cimport GetComponentsOfApp
from primo.linking.target_data cimport GetComponentsWithKind
from primo.linking.target_data cimport GetComponentsWithName
from primo.linking.target_data cimport GetExportedComponentCount
from primo.linking.target_data cimport GetExportedComponents
from primo.linking.intents cimport Intent


DTYPE = np.int8


LOGGER = logging.getLogger(__name__)


cdef class ExplicitLinkFinder(object):
  """Class storing the counts of explicit links."""

  def __cinit__(self):
    self._intra_app = 0
    self._inter_app = 0
    self._probability_intra_app = -1
    self._probability_inter_app = -1
    self._CACHE = ({}, {}, {})

  cdef void IncrementIntraApp(self):
    if self._probability_intra_app > 0:
      LOGGER.error('Should not increment the number of intra-app links after '
                   'computing probabilities.')
      raise Exception
    self._intra_app += 1

  cdef void IncrementInterApp(self):
    if self._probability_intra_app > 0:
      LOGGER.error('Should not increment the number of inter-app links after '
                   'computing probabilities.')
      raise Exception
    self._inter_app += 1

  cdef float GetInterAppProbability(self):
    """Returns the probability of having inter-app explicit links.

    After querying this method, self.inter_app should no longer be updated.
    """

    if self._probability_inter_app < 0:
      if self._intra_app + self._inter_app == 0:
        self._probability_inter_app = 0
      self._probability_inter_app = (float(self._inter_app) /
                                     (self._intra_app + self._inter_app))
    return self._probability_inter_app

  cdef float GetIntraAppProbability(self):
    """Returns the probability of having intra-app explicit links.

    After querying this method, self.intra_app should no longer be updated.
    """

    if self._probability_intra_app < 0:
      if self._intra_app + self._inter_app == 0:
        self._probability_intra_app = 0
      self._probability_intra_app = (float(self._intra_app) /
                                     (self._intra_app + self._inter_app))
    return self._probability_intra_app

  @cython.boundscheck(False)
  cdef tuple FindExplicitLinksForIntent(
      self, Intent current_intent, set components, bint compute_link_attribute,
      bint validate):
    IF DEBUG:
      LOGGER.debug("initially %s", len(components))

    cdef unicode dclass = current_intent.dclass
    if dclass != '(.*)':
      components = GetComponentsWithName(dclass, components)
      IF DEBUG:
        LOGGER.debug("after class %s", len(components))
    if len(components) == 0:
      return None

    cdef unicode dpackage = current_intent.dpackage
    if dpackage is not None and dpackage != '(.*)':
      components = GetComponentsOfApp(dpackage, components)
      IF DEBUG:
        LOGGER.debug("after package %s", len(components))
    if len(components) == 0:
      return None

    components = self.ExplicitVisibilityTest(current_intent, components)
    IF DEBUG:
      LOGGER.debug("after visibility %s", len(components))
    if not components:
      return None

    components = self.ExplicitKindTest(current_intent, components)
    IF DEBUG:
      LOGGER.debug("after kind %s", len(components))
    if len(components) == 0:
      return None

    cdef list targets
    cdef DTYPE_t current_link_attribute
    cdef np.ndarray[DTYPE_t, ndim=1] attributes
    cdef Py_ssize_t index

    cdef int components_size = len(components)

    cdef Component component
    if components_size == 0:
      return None

    index = 0
    targets = list(components)

    attribute_computation_time = 0

    if compute_link_attribute:
      start = time.time()
      attributes = np.empty(components_size, dtype=DTYPE)
      for component in targets:
        current_link_attribute = self.GetProbabilityForExplicitIntent(
            current_intent, component)
        attributes[index] = current_link_attribute
        index += 1
      attribute_computation_time = time.time() - start
    if current_intent.IsPrecise():
      if current_intent.application.name == component.application.name:
        self.IncrementIntraApp()
      else:
        self.IncrementInterApp()

    return targets, attributes, attribute_computation_time


  cdef set ExplicitKindTest(self, Intent intent, set initial_cut):
    return GetComponentsWithKind(intent.exit_kind, initial_cut)


  cdef set ExplicitVisibilityTest(self, Intent intent, set initial_cut):
    return ((set(intent.application_components) & initial_cut)
            | GetExportedComponents(initial_cut))

  @cython.cdivision(True)
  cdef DTYPE_t GetProbabilityForExplicitIntent(self, Intent intent,
                                               Component target):
    if intent.IsPrecise():
      return <DTYPE_t> 100

    cdef int exit_kind = intent.exit_kind
    cdef set matching_apps
    cdef int apps_with_exported_components
    cdef Application app
    cdef bint components_in_sending_app
    cdef Application target_application = target.application
    cdef unicode dclass = intent.dclass
    cdef int pi = target_application.CountMatchingComponentsOfKind(exit_kind,
                                                                   dclass)
    cdef unicode dpackage = intent.dpackage
    cdef tuple key
    if dpackage is None or '(.*)' in dpackage:
      app = intent.application
      if app.name == target_application.name:
        return <DTYPE_t> ((100.0 / pi) * self.GetIntraAppProbability())
      else:
        key = (dpackage, dclass)
        try:
          apps_with_exported_components = self._CACHE[exit_kind][key]
        except KeyError:
          matching_apps = GetAppsMatching(dpackage, dclass)
          apps_with_exported_components = GetExportedComponentCount(exit_kind,
                                                                    matching_apps)
          self._CACHE[exit_kind][key] = apps_with_exported_components
        components_in_sending_app = app.HasMatchingExportedComponentsOfKind(
            exit_kind, dclass)
        if components_in_sending_app:
          apps_with_exported_components -= 1
        return <DTYPE_t> ((100.0 / (pi * apps_with_exported_components))
                          * self.GetInterAppProbability())
    else:
      return <DTYPE_t> (100.0 / pi)
