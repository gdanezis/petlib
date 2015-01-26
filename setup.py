#!/usr/bin/env python

from distutils.core import setup

## Need to import the CFFI module during installation to ensure it 
## builds the packages, and places them in the right context.
try:
      import petlib.bindings
      deps = [petlib.bindings._FFI.verifier.get_extension()]
except Exception as e:
      import traceback
      traceback.print_exc()
      print("Alter: Not compiling the library -- useful for readthedocs.")
      deps = []

import petlib

setup(name='petlib',
      version=petlib.VERSION,
      description='A library implementing a number of Privacy Enhancing Technologies (PETs)',
      author='George Danezis',
      author_email='g.danezis@ucl.ac.uk',
      url=r'https://pypi.python.org/pypi/petlib/',
      packages=['petlib'],
      ext_package='petlib',
      license="2-clause BSD",
      long_description="""A library wrapping Open SSL low-level cryptographic libraries to build Privacy Enhancing Technoloies (PETs)""",
      install_requires=[
            "cffi >= 0.8.2",
            "future >= 0.14.3",
            "pytest >= 2.6.4",
            "paver >= 1.2.3",
            "pytest-cov >= 1.8.1",
      ],
      zip_safe=False,
      ext_modules=deps,
)