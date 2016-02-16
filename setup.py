#!/usr/bin/env python

import os, sys
from distutils.core import setup
from setuptools.command.install import install as _install

## Post-installation runninf of the core test-suite 

def _post_install(dir):
    try:
        import petlib
        petlib.run_tests()
    except Exception as e:
        print("Tests failed.")
        import traceback
        traceback.print_exc()


class install(_install):
    def run(self):
        _install.run(self)
        self.execute(_post_install, (self.install_lib,),
                     msg="Running post install task")


import petlib

try:
    from petlib.compile import _FFI
    deps = [ _FFI.distutils_extension() ]
except:
    print "Failed to compile."
    deps = [ ]

setup(name='petlib',
      version=petlib.VERSION,
      description='A library implementing a number of Privacy Enhancing Technologies (PETs)',
      author='George Danezis',
      author_email='g.danezis@ucl.ac.uk',
      url=r'https://pypi.python.org/pypi/petlib/',
      packages=['petlib'],
      ext_package='_petlib',
      license="2-clause BSD",
      long_description="""A library wrapping Open SSL low-level cryptographic libraries to build Privacy Enhancing Technoloies (PETs)""",

      setup_requires=["cffi>=1.0.0",
                      "pytest >= 2.6.4"],
      cffi_modules=["petlib/compile.py:_FFI"],
      
      # install_requires=reqs,
      install_requires=[
            "cffi >= 1.0.0",
            "pycparser >= 2.10",
            "future >= 0.14.3",
            "pytest >= 2.6.4",
            "paver >= 1.2.3",
            "pytest-cov >= 1.8.1",
            "msgpack-python >= 0.4.6",
      ],
      ext_modules=deps,
      zip_safe=False,
      # ext_modules=deps,
      # Custom install with post processing
      cmdclass={'install': install},
)