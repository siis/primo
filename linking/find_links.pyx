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
"""Compute links between Intents and Intent Filters."""

from collections import Counter
import logging
import sys
import time
import traceback

import gflags

from linking.find_explicit_links cimport ExplicitLinkFinder
from linking.find_implicit_links cimport ImplicitLinkFinder
from linking.target_data cimport PrepareForQueries
from linking.intent_data cimport GetImpreciseComponentIntents
from linking.intent_data cimport GetPreciseComponentIntents
from linking.intents cimport ComponentIntent
from linking.intents cimport Intent
from linking.validation cimport PerformValidation

from linking import fetch_data
from linking import intents as intents_mod
from linking import write_results


gflags.DEFINE_boolean('computeattributes', True, 'Compute attributes.')

FLAGS = gflags.FLAGS


LOGGER = logging.getLogger(__name__)


def FindLinksAndLogExceptions(protobufs, protodirs=None, skip_empty=False,
                              stats=None, dump_results=None, validate=None):
  """Wrapper that catches and logs exceptions for the Intent matching procedure.

  Args:
    protobufs: A list of paths to protobufs.
    protodirs: A list of paths to directories that contain protobufs.
    skip_empty: Indicates whether empty Intents should be skipped.
    stats: If not None, gives the path of a file where statistics should be
    stored.
    dump_results: If not None, indicates the path of a file where links should
    be dumped in a compressed binary format.
    validate: Indicates whether cross-validation should be performed.

  Returns: A tuple with the Intent links, the components, the Intent Filters,
  the applications and the Intents.
  """

  try:
    return FindLinks(protobufs, protodirs, skip_empty, stats, dump_results,
                     validate)
  except:
    etype, msg, tb = sys.exc_info()
    LOGGER.error('Caught exception %s: %s\n%s', etype, msg,
                 '\n'.join(traceback.format_tb(tb)))


def FindLinks(protobufs, protodirs=None, skip_empty=False, stats=None,
              dump_results=None, validate=None):
  """Computes the links between Intents and Intent Filters.

  Args:
    protobufs: A list of paths to protobufs.
    protodirs: A list of paths to directories that contain protobufs.
    skip_empty: Indicates whether empty Intents should be skipped.
    stats: If not None, gives the path of a file where statistics should be
    stored.
    dump_results: If not None, indicates the path of a file where links should
    be dumped in a compressed binary format.
    validate: Indicates whether cross-validation is being performed.

  Returns: A tuple with the Intent links, the components, the Intent Filters,
  the applications and the Intents.
  """

  cdef list statistics = None
  cdef ExplicitLinkFinder explicit_link_finder
  cdef ImplicitLinkFinder implicit_link_finder = ImplicitLinkFinder()

  if stats is not None:
    statistics = []
  cdef dict intent_links = {}

  applications, components, intents, intent_filters = fetch_data.FetchData(
      protobufs, protodirs)
  PrepareForQueries(applications)

  if stats is not None:
    statistics.append(len(applications))

  cdef float start = time.time()

  if validate:
    PerformValidation(intents, skip_empty, components, intent_filters, validate)
    return intent_links, components, intent_filters, applications, intents

  intent_links, link_count, skipped_empty, intent_count, explicit, \
      attribute_time, explicit_link_finder = FindLinksForIntents(
          GetPreciseComponentIntents(), GetImpreciseComponentIntents(),
          skip_empty, components, intent_filters, FLAGS.computeattributes,
          False)

  LOGGER.info('Done processing all Intents.')

  cdef float end
  cdef float duration

  if stats is not None:
    end = time.time()
    duration = end - start

    statistics += intents_mod.CalculateIntentExpectation()

    statistics.append(intent_count)
    statistics.append(explicit)
    statistics.append(len(components))
    statistics.append(len(intent_filters))
    statistics.append(duration)

    print 'There are %d intent links.' % link_count
    statistics.append(link_count)

    statistics.append(0)
    statistics.append(0)
    statistics.append(0)
    statistics.append(explicit_link_finder.GetInterAppProbability())
    statistics.append(explicit_link_finder.GetIntraAppProbability())
    statistics.append(skipped_empty)
    statistics.append(attribute_time)

    with open(stats, 'a') as stats_file:
      stats_file.write(','.join([str(element) for element in statistics])
                       + '\n')

  if dump_results:
    write_results.WriteResults(intent_links, link_count, dump_results)
  return intent_links, components, intent_filters, applications, intents


def FindLinksForIntents(precise_intents, imprecise_intents, skip_empty,
                        components, intent_filters, include_attributes,
                        validation=False):
  """Computes the links between Intents and Intent Filters.

  Args:
    precise_intents: A list of precise Intents.
    imprecise_intents: A list of imprecise Intents.
    skip_empty: Indicates whether empty Intents should be skipped.
    components: The set of potential target components.
    intent_filters: The set of potential target Intent Filters.
    include_attributes: If True, link probabilities will be computed.
    validation: Indicates whether cross-validation is being performed.

  Returns: A tuple with the Intent links, the components, the Intent Filters,
  the applications and the Intents.
  """

  cdef ExplicitLinkFinder explicit_link_finder = ExplicitLinkFinder()
  cdef ImplicitLinkFinder implicit_link_finder = ImplicitLinkFinder()
  cdef int intent_count = 0
  cdef int skipped_empty = 0
  cdef int explicit_intent_count = 0
  cdef dict intent_links = {}
  cdef long link_count = 0
  cdef float total_attribute_time = 0.0
  cdef ComponentIntent component_intent
  LOGGER.info('Started processing precise Intents.')
  for component_intent in precise_intents:
    if skip_empty and component_intent.IsEmpty():
      skipped_empty += 1
      continue
    links, explicit_count, attribute_time = FindLinksForIntent(
        component_intent, intent_links, components, intent_filters,
        True, include_attributes, explicit_link_finder, implicit_link_finder,
        validation)
    link_count += links
    explicit_intent_count += explicit_count
    intent_count += 1
    total_attribute_time += attribute_time
  if validation:
    intent_links = {}

  LOGGER.info('Done processing precise Intents.')
  LOGGER.info('Started processing imprecise Intents.')
  for component_intent in imprecise_intents:
    if skip_empty and component_intent.IsEmpty():
      skipped_empty += 1
      continue
    links, explicit_count, attribute_time = FindLinksForIntent(
        component_intent, intent_links, components, intent_filters,
        False, include_attributes, explicit_link_finder, implicit_link_finder,
        validation)
    link_count += links
    explicit_intent_count += explicit_count
    intent_count += 1
    total_attribute_time += attribute_time
  LOGGER.info('Done processing imprecise Intents.')

  return (intent_links, link_count, skipped_empty, intent_count,
          explicit_intent_count, total_attribute_time, explicit_link_finder)


cdef tuple FindLinksForIntent(
    ComponentIntent component_intent, dict intent_links, set components,
    set intent_filters, bint precise_intent, bint include_attributes,
    ExplicitLinkFinder explicit_link_finder,
    ImplicitLinkFinder implicit_link_finder, bint validate=False):
  """Computes all the potential targets for a given Intent.

  Args:
    component_intent: The Intent for which potential targets should be computed.
    intent_links: The map of Intent links to which the results should be added.
    components: The potential target components.
    intent_filters: The potential target Intent Filters.
    precise_intent: Indicates if the argument Intent is precise.
    include_attributes: If True, link probabilities will be computed.
    explicit_link_finder: An ExplicitLinkFinder object.
    implicit_link_finder: An ImplicitLinkFinder object.
    validate: Indicates whether cross-validation is being performed.

  Returns: A tuple with the number of computed links, the number of explicit
  Intents (0 or 1) and the time taken for computing the link probabilities.
  """

  cdef Intent intent = component_intent.intent

  LOGGER.info('Processing Intent %s', component_intent.id)
  LOGGER.info(component_intent)

  cdef float attribute_time

  if intent.dclass is not None:
    targets_and_attributes = explicit_link_finder.FindExplicitLinksForIntent(
        intent, components, True, validate)
    explicit_intent_count = 1
  else:
    targets_and_attributes = implicit_link_finder.FindImplicitLinksForIntent(
        component_intent, intent_filters, True, precise_intent, validate)
    explicit_intent_count = 0
  cdef long links = 0
  if targets_and_attributes:
    attribute_time = targets_and_attributes[2]
    targets = targets_and_attributes[0]
    links += len(targets)

    if include_attributes:
      intent_links[component_intent] = (targets,
                                        targets_and_attributes[1])
    else:
      intent_links[component_intent] = targets
  else:
    attribute_time = 0.0

  return links, explicit_intent_count, attribute_time
