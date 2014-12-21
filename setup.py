#!/usr/bin/env python

from distutils.core import setup

setup(name='petlib',
      version='0.0.12',
      description='A library implementing a number of Privacy Enhancing Technologies (PETs)',
      author='George Danezis',
      author_email='g.danezis@ucl.ac.uk',
      url=r'https://pypi.python.org/pypi/petlib/',
      # data_files=[('examples', ['examples/toyrsa.py'])],
      packages=['petlib'],
      license="2-clause BSD",
      long_description="""A library wrapping Open SSL low-level cryptographic libraries to build Privacy Enhancing Technoloies (PETs)""",
      install_requires=[
            "cffi >= 0.8.2"
      ],
)