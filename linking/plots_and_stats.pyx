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
"""Functions for drawing plots and writing statistics to a .tex file.

Some parameters in these functions take some trial and error and the current
parameters are appropriate for the data in the paper.
"""

cimport numpy as np

import locale
import logging
import os.path

from matplotlib import pyplot
from matplotlib import rcParams
import bloscpack as bp
import matplotlib
import numpy as np

from linking.write_results cimport Row


FONT_SIZE = 22

rcParams['axes.labelsize'] = FONT_SIZE
rcParams['xtick.labelsize'] = FONT_SIZE
rcParams['ytick.labelsize'] = FONT_SIZE
rcParams['legend.fontsize'] = FONT_SIZE
rcParams['font.family'] = 'serif'
# IF UNAME_SYSNAME == "Darwin":
rcParams['font.serif'] = ['Times New Roman']
# ELSE:
#   path = '/usr/share/fonts/truetype/msttcorefonts/Times_New_Roman.ttf'
#   rcParams['font.serif'] = ['Times_New_Roman']
# rcParams['text.usetex'] = True
rcParams['figure.figsize'] = 7.3, 4.2


def MakePlotsAndStats(input, output):
  """Draws all plots and records various statistics to .tex files.

  Args:
    input: The input links file.
    output: The output directory where the plots should be saved.
  """

  # This allows us to output numbers in the form 1,000,000 instead of 1000000.
  locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
  logging.info('Loading file %s.', input)
  cdef np.ndarray[Row] links = bp.unpack_ndarray_file(input)
  logging.info('Loaded %d Intent links.', links.shape[0])

  cdef np.ndarray[np.int32_t] intents = links[:]['intent']
  cdef np.ndarray[np.int64_t] connectivities

  with open(os.path.join(output, 'other-results.tex'), 'w') as results_file:
    results_file.write(locale.format_string(
        '\\newcommand{\\linkcount}{%d}\n', links.size, grouping=True))
    PlotPriorityDistribution(links, results_file, output)
    PlotPriorityDistributionInterIntra(links, output)
    logging.info('Computing Intent connectivities.')
    connectivities = np.unique(intents, return_counts=True)[1]
    logging.info('Finished computing Intent connectivities from Intent links.')
    ConnectivityCdf(connectivities, results_file, output)
    LinksCdf(connectivities, results_file, output)


cdef void PlotCdf(data, str xlabel, str ylabel, str destination, float x_min,
                  float y_min, object bins):
  """Plots a cumulative distribution function.

  Args:
    data: The data.
    xlabel: The label for the X axis.
    ylabel: The label for the Y axis.
    destination: The destination file.
    x_min: The lower bound for the X axis.
    y_min: The lower bound for the Y axis.
    bins: The histogram bins.
  """

  cdef float x_max = data.max()
  pyplot.figure()
  pyplot.xlabel(xlabel)
  pyplot.ylabel(ylabel)
  pyplot.xscale('log')
  pyplot.grid(which='both', color='0.7')
  vals, bins, _ = pyplot.hist(data, bins, normed=True, cumulative=True,
                              histtype='step')
  x_max = x_max + (x_max - x_min) / 200
  pyplot.xlim([x_min, x_max])
  pyplot.ylim([y_min, 1])
  pyplot.savefig(os.path.join(destination), bbox_inches='tight', pad_inches=0.1)


cdef void ConnectivityCdf(np.ndarray[np.int64_t] connectivities,
                          object results_file, str output):
  """Plots the CDF of connectivity and writes some statistics to a .tex file.

  Args:
    connectivities: Connectivity data.
    results_files: An open .tex file.
    output: The path to the destination file.
  """

  logging.info('Computing connectivity CDFs.')

  cdef int total = connectivities.size

  results_file.write('\\newcommand{\\intentsltone}{%.0f\\%%}\n' %
                     (100.0 * CountLessThan(connectivities, 1) / total))
  results_file.write('\\newcommand{\\intentsltonehundred}{%.0f\\%%}\n' %
                     (100.0 * CountLessThan(connectivities, 100) / total))
  results_file.write(locale.format_string(
      '\\newcommand{\\maxconnectivity}{%d}\n', connectivities.max(),
      grouping=True))

  PlotCdf(connectivities, 'Number of potential Intent targets (log scale)',
          'CDF of Intents',
          os.path.join(output, 'intent_connectivity_cdf.pdf'), 1, 0.5,
          np.logspace(0, np.ceil(np.log10(connectivities.max())), 1000))


cdef void LinksCdf(np.ndarray[np.int64_t] connectivities, object results_file,
                   str output):
  """Plots the CDF of connectivities and writes some statistics to a .tex file.

  Args:
    connectivities: Connectivity data.
    results_file: An open .tex file.
    output: The path to the destination file.
  """

  logging.info('Plotting link CDF.')

  connectivities = np.sort(connectivities)[::-1]
  cdef np.int64_t x_max = connectivities.size
  pyplot.figure()
  pyplot.hist(range(1, x_max + 1),
              bins=np.logspace(0, np.ceil(np.log10(x_max)), 1000),
              normed=True, weights=connectivities, cumulative=True,
              histtype='step')
  pyplot.xscale('log')
  pyplot.xlim([100, x_max])
  pyplot.ylim([0, 1])
  pyplot.xlabel('Intents (log scale)')
  pyplot.ylabel('CDF of links')
  pyplot.grid(which='both', color='0.7')
  pyplot.savefig(os.path.join(output, 'link_cdf.pdf'), bbox_inches='tight',
                 pad_inches=0.1)

  logging.info('Finished plotting link CDF.')

  connectivities = connectivities.cumsum()
  results_file.write('\\newcommand{\\eightypercentlinks}{%.0f\\%%}\n' %
                     (100.0 * CountLessThan(connectivities, 0.8 * connectivities[-1]) /
                      connectivities.size))


cdef int CountLessThan(data, threshold):
  """Counts how many entries are less than or equal to a certain value.

  Args:
    data: The data.
    threshold: The upper bound.
  """

  return (data <= threshold).sum()


cdef void PlotHistogram(data, str xlabel, str ylabel, str destination,
                        yticks=None):
  """Plots a histogram.

  Args:
    data: The data.
    xlabel: The label for the X axis.
    ylabel: The label for the Y axis.
    destination: The path to the destination file.
    yticks: Ticks for the Y axis.
  """

  figure = pyplot.figure()
  data = np.clip(data, 0, 1)
  vals, bins, _ = pyplot.hist(data, 50, normed=False, cumulative=False)
  pyplot.xlabel(xlabel)
  pyplot.ylabel(ylabel)
  pyplot.yscale('log', nonposy='clip')
  pyplot.grid(axis='y', color='0.6')
  if yticks is not None:
    pyplot.yticks(yticks)
  pyplot.savefig(destination, bbox_inches='tight', pad_inches=0.1)


cdef void PlotPriorityDistribution(np.ndarray[Row] intent_links,
                                   object results_file, str output):
  """Plots the distribution of probability values and writes some statistics to
  a .tex file.

  Args:
    intent_links: The Intent links array.
    results_file: An open .tex file.
    output: The path to the destination directory.
  """

  logging.info('Plotting probability distribution CDF.')

  cdef np.ndarray[np.float32_t] priorities = \
      intent_links[:]['probability'].astype(np.float32)

  priorities /= 100

  PlotCdf(priorities, 'Probability $P_{i, f}$ (log scale)',
          'CDF of links',
          os.path.join(output, 'probability_cdf.pdf'), 1e-2, 0.95,
          np.linspace(0, 1, 500))
  logging.info('Finished plotting probability distribution CDF.')

  logging.info('Plotting probability distribution histogram.')
  PlotHistogram(priorities, 'Probability $P_{i, f}$',
                'Link count (log scale)',
                os.path.join(output, 'probability_hist.pdf'))
  logging.info('Finished plotting probability distribution histogram.')


cdef void PlotPriorityDistributionInterIntra(np.ndarray[Row] links, str output):
  """Plots the distribution of probabilities for various combinations of
  explicit/implicit Intents and inter/intra-application links.

  Args:
    links: The Intent links.
    output: The path to the output directory.
  """

  logging.info('Plotting probability distribution by inter/intra app Intent.')

  cdef np.ndarray[np.float32_t] data
  data = links[(links[:]['explicit'] == 1) &
               (links[:]['intra_app'] == 1)][:]['probability'].astype(
                   np.float32)
  rcParams['axes.labelsize'] = 32
  rcParams['xtick.labelsize'] = 32
  rcParams['ytick.labelsize'] = 32
  rcParams['legend.fontsize'] = 32
  data /= 100
  PlotHistogram(data, 'Probability $P_{i, f}$', 'Link count (log scale)',
                os.path.join(output, 'expl_intra.pdf'))

  data = links[(links[:]['explicit'] == 1) &
               (links[:]['intra_app'] == 0)][:]['probability'].astype(
                   np.float32)
  data /= 100
  PlotHistogram(data, 'Probability $P_{i, f}$', 'Link count (log scale)',
                os.path.join(output, 'expl_inter.pdf'))

  data = links[(links[:]['explicit'] == 0) &
               (links[:]['intra_app'] == 0)][:]['probability'].astype(
                   np.float32)
  data /= 100
  PlotHistogram(data, 'Probability $P_{i, f}$', 'Link count (log scale)',
                os.path.join(output, 'impl_inter.pdf'),
                yticks=[1, 1e2, 1e4, 1e6, 1e8])

  data = links[(links[:]['explicit'] == 0) &
               (links[:]['intra_app'] == 1)][:]['probability'].astype(
                   np.float32)
  data /= 100
  PlotHistogram(data, 'Probability $P_{i, f}$', 'Link count (log scale)',
                os.path.join(output, 'impl_intra.pdf'))
  logging.info('Finished plotting histograms.')
  rcParams['axes.labelsize'] = FONT_SIZE
  rcParams['xtick.labelsize'] = FONT_SIZE
  rcParams['ytick.labelsize'] = FONT_SIZE
  rcParams['legend.fontsize'] = FONT_SIZE
