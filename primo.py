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
"""Compute ICC links.

     Usage: primo
       [--protobuf <path to protobuf>]
       [--protodir <path to protobuf directory>]
       [--protobufs <protobuf, protobuf, ...>]
       [--skipempty]
       [--verbose <0 | 1 | 2>]
       [--dumpintentlinks <path to link output file>]
       [--stats <path to the stats output file>]
       [--validate <k1, k2, ...>]
       [--computeattributes]
"""

import logging
import sys
import time

import gflags

from linking import find_links


FLAGS = gflags.FLAGS

gflags.DEFINE_integer('verbose', 1, 'Verbose mode.', short_name='v')
gflags.DEFINE_boolean('skipempty', False, 'Skip empty Intents.')
gflags.DEFINE_string('dumpintentlinks', None, 'Dump Intent links.')
gflags.DEFINE_multistring('protobuf', [], 'A protobuf.')
gflags.DEFINE_list('protobufs', [], 'A comma-separated list of protobufs.')
gflags.DEFINE_multistring('protodir', None, 'A directory with protobufs.')
gflags.DEFINE_string('stats', None, 'Write some statistics to a file.')
gflags.DEFINE_list('validate', None, ('Perform k-fold cross-validation (k is '
                                      'the argument).'))


def main(argv):
  """Entry point."""

  try:
    argv = FLAGS(argv)
  except gflags.FlagsError as exception:
    print >> sys.stderr, ('Error while processing command line flags: %s'
                          % str(exception))
    sys.exit(1)

  log_formatter = logging.Formatter('%(asctime)s [%(name)s] '
                                    '[%(levelname)-5.5s]  %(message)s')
  root_logger = logging.getLogger()
  if FLAGS.verbose == 0:
    root_logger.setLevel(logging.WARN)
  elif FLAGS.verbose == 1:
    root_logger.setLevel(logging.INFO)
  elif FLAGS.verbose == 2:
    root_logger.setLevel(logging.DEBUG)
  time_and_date = time.strftime('%Y%m%d-%H-%M-%S')
  file_handler = logging.FileHandler('linking_%s.log' % time_and_date)
  file_handler.setFormatter(log_formatter)
  root_logger.addHandler(file_handler)

  console_handler = logging.StreamHandler()
  console_handler.setFormatter(log_formatter)
  root_logger.addHandler(console_handler)

  find_links.FindLinks(FLAGS.protobuf + FLAGS.protobufs, FLAGS.protodir,
                       FLAGS.skipempty, FLAGS.stats, FLAGS.dumpintentlinks,
                       FLAGS.validate)


if __name__ == '__main__':
  main(sys.argv)
