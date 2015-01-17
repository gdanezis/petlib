#!/usr/bin/env python

from distutils.core import setup

## Need to import the CFFI module during installation to ensure it 
## builds the packages, and places them in the right context.
try:
      import petlib.bindings
      deps = [petlib.bindings._FFI.verifier.get_extension()]
except:
      print("Alter: Not compiling the library -- useful for readthedocs.")
      deps = []

setup(name='petlib',
      version='0.0.22',
      description='A library implementing a number of Privacy Enhancing Technologies (PETs)',
      author='George Danezis',
      author_email='g.danezis@ucl.ac.uk',
      url=r'https://pypi.python.org/pypi/petlib/',
      packages=['petlib'],
      license="2-clause BSD",
      long_description="""A library wrapping Open SSL low-level cryptographic libraries to build Privacy Enhancing Technoloies (PETs)""",
      install_requires=[
            "cffi >= 0.8.2",
            "future >= 0.14.3",
            "pytest >= 2.6.4",
            "paver >= 1.2.3",
            "pytest-cov >= 1.8.1",
      ],
      ext_modules=deps,
)