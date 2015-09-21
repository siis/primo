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

"""Module for performing performance experiments with PRIMO."""

from multiprocessing import Process
from random import randint
import glob
import logging
import os
import sys
import time

import gflags

from linking.find_links import FindLinksAndLogExceptions


LOGGER = logging.getLogger(__name__)


FLAGS = gflags.FLAGS

gflags.DEFINE_multistring('protodir', None, 'A directory with protobufs.')
gflags.MarkFlagAsRequired('protodir')
gflags.DEFINE_string('stats', None, 'A statistics file name.')
gflags.MarkFlagAsRequired('stats')
gflags.DEFINE_string('datapoints', None, 'A file with data points.')
gflags.MarkFlagAsRequired('datapoints')
gflags.DEFINE_boolean('skipempty', False, 'Skip empty Intents.')


def RunExperiments(protobufs, data_points, file_path):
  protobuf_count = len(protobufs)

  for size, count in reversed(data_points):
    if size < protobuf_count:
      for _ in range(count):
        RunExperimentForSize(protobufs, size, file_path)
        LOGGER.info('Processed %s apps.')

  RunExperimentForSize(protobufs, protobuf_count, file_path)


def RunExperimentForSize(protobufs, size, stats):
  selection = set()
  protobuf_count = len(protobufs)
  LOGGER.info('Processing %s apps.', size)

  if size < protobuf_count:
    while size > 0:
      index = randint(0, protobuf_count - 1)
      protobuf = protobufs[index]
      if protobuf in selection:
        continue
      selection.add(protobuf)
      size -= 1
  else:
    selection = protobufs

  LOGGER.info('Selected %s protobufs.', len(selection))
  process = Process(target=FindLinksAndLogExceptions,
                    kwargs={'protobufs': selection, 'stats': stats,
                            'skip_empty': True})
  process.start()
  process.join()

  LOGGER.info('test %s', os.getpid())


def LoadDataPoints(data_points_path):
  data_points = []

  with open(data_points_path) as data_points_file:
    for line in data_points_file:
      if line:
        line = line.rstrip('\n')
        line_parts = line.split(',')
        if len(line_parts) != 2:
          LOGGER.warn('Ignoring unknown line %s', line)
        data_points.append([int(element) for element in line_parts])

  return data_points


def LoadProtoList():
  result = []
  for protodir in FLAGS.protodir:
    result += glob.glob(os.path.join(protodir, '*'))

  LOGGER.info('Loaded %s protobufs.', len(result))
  return result


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
  root_logger.setLevel(logging.WARN)
  LOGGER.setLevel(logging.INFO)
  start_time = time.strftime('%Y%m%d-%H:%M:%S')
  file_handler = logging.FileHandler('linking_%s.log' % start_time)
  file_handler.setFormatter(log_formatter)
  root_logger.addHandler(file_handler)

  console_handler = logging.StreamHandler()
  console_handler.setFormatter(log_formatter)
  root_logger.addHandler(console_handler)

  data_points = LoadDataPoints(FLAGS.datapoints)
  protobufs = LoadProtoList()
  RunExperiments(protobufs, data_points, FLAGS.stats)


if __name__ == '__main__':
  main(sys.argv)
