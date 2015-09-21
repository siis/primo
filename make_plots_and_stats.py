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

"""Entry point for module that draws plots and computes statistics of Intent
links."""

import logging
import sys

import gflags

from linking.plots_and_stats import MakePlotsAndStats


FLAGS = gflags.FLAGS

gflags.DEFINE_string('input', None, 'Input file.')
gflags.MarkFlagAsRequired('input')
gflags.DEFINE_string('out', None, 'Output directory.')
gflags.MarkFlagAsRequired('out')


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
  root_logger.setLevel(logging.INFO)

  console_handler = logging.StreamHandler()
  console_handler.setFormatter(log_formatter)
  root_logger.addHandler(console_handler)

  MakePlotsAndStats(FLAGS.input, FLAGS.out)


if __name__ == '__main__':
  main(sys.argv)
