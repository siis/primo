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

import glob
import os
import numpy
from setuptools import setup, Extension


SRC_DIR = 'primo/linking'

NAME = 'primo'
VERSION = '0.1.0'
DESCR = 'ICC resolution package.'
URL = 'http://siis.cse.psu.edu/primo/'

AUTHOR = 'Damien Octeau'
EMAIL = 'octeau@cse.psu.edu'

LICENSE = 'Apache 2.0'

REQUIRES = ['numpy', 'scipy', 'protobuf', 'python-gflags', 'bloscpack']

PACKAGES = ['primo', 'primo.linking']
SCRIPTS = ['bin/primo', 'bin/make_plots_and_stats',
      'bin/performance_experiments']
CMD_CLASS = {}
OPTIONS = {}

if glob.glob(os.path.join(SRC_DIR, '*.c')):
  # We don't ship .pyx files with a source distribution so that users don't have
  # to cythonize everything again.
  # See http://docs.cython.org/src/reference/compilation.html#distributing-cython-modules.
  USE_CYTHON = False
elif glob.glob(os.path.join(SRC_DIR, '*.pyx')):
  try:
    from Cython.Build import cythonize
    from setuptools.command.build_ext import build_ext
    USE_CYTHON = True
  except ImportError as e:
    # It won't be possible to compile or cythonize files.
    print(e)
    exit(1)
else:
  print("No .pyx or .c files.")
  exit(1)

def ScanDir(directory, file_extension, files=[]):
  """Scans the 'linking' directory for extension files, converting
  them to extension names in dotted notation."""

  for file_name in os.listdir(directory):
    file_path = os.path.join(directory, file_name)
    if os.path.isfile(file_path) and file_path.endswith(file_extension):
      files.append(file_path.replace(os.path.sep, '.')[:-len(file_extension)])
    elif os.path.isdir(file_path):
      ScanDir(file_path, file_extension, files)
  return files

def MakeExtension(ext_name, file_extension):
  """Generates an Extension object from its dotted name."""

  ext_path = ext_name.replace(".", os.path.sep) + file_extension
  return Extension(
      ext_name,
      [ext_path],
      include_dirs = ['.', numpy.get_include()],
      extra_compile_args = ['-O3', '-Wall'],
      extra_link_args = ['-g'],
      )

if __name__ == "__main__":
  if USE_CYTHON:
    extension = '.pyx'
    CMD_CLASS['build_ext'] = build_ext
    OPTIONS['build_ext'] = {'inplace':True}
    REQUIRES.append('Cython')
  else:
    extension = '.c'

  # Get the list of extensions.
  ext_names = ScanDir('primo', extension)

  # And build up the set of Extension objects.
  extensions = [MakeExtension(name, extension) for name in ext_names]
  if USE_CYTHON:
      extensions = cythonize(extensions)

  setup(packages=PACKAGES,
        name=NAME,
        version=VERSION,
        description=DESCR,
        author=AUTHOR,
        author_email=EMAIL,
        url=URL,
        scripts=SCRIPTS,
        license=LICENSE,
        install_requires=REQUIRES,
        cmdclass=CMD_CLASS,
        ext_modules=extensions,
        options=OPTIONS
        )
