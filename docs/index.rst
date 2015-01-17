.. petlib documentation master file, created by
   sphinx-quickstart on Sun Nov 23 00:41:16 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to petlib's documentation!
==================================

Contents
--------

.. toctree::
   :maxdepth: 2

   index


Installation and Dependences
----------------------------

petlib requires a number of packages, including:
  * A working installation of OpenSSL > 1.0.1.
  * A working instalation of python packages cffi, pytest, paver.

To install pelib and the python dependencies you may use the pip package manager::

  pip install petlib

Testing and Packaging
---------------------

To build the distribution, create a venv for tests and run all tests (including the examples)::

  paver

Specific paver targets include:
  * ``unit_tests``: runs the unit tests.
  * ``build``: builds a distribution bundle in the ``dist`` directory.
  * ``make_docs``: builds the html documentation in ``docs/_build/html``
  * ``make_env``: initialized a virtualenv with a fresh petlib in folder ``test_env/pltest``.
  * ``big_test``: runs all the examples in a virtual environment.
  * ``test``: runs all tests.

**Under the hood.** Petlib uses `py.test`_ for managing and running unit tests, and the `pytest-cov`_ module for test coverage. For running all tests and generating a code coverage report run::

	py.test --doctest-modules --cov petlib petlib/*.py

.. _py.test: http://pytest.org
.. _pytest-cov: https://pypi.python.org/pypi/pytest-cov

To generate an HTML report of lines not covered by tests run::

	py.test --doctest-modules --cov-report html --cov petlib petlib/*.py

To build the Sphinx_ HTML documentation go into ``docs`` and run::

	make html

.. _Sphinx: http://sphinx-doc.org/

To build the source distribution run (and add ``upload`` if you wish to upload it to pypi)::

	python setup.py sdist

petlib Modules
==============

.. automodule:: petlib

Module petlib.bn
----------------
 
.. autoclass:: petlib.bn.Bn
    :members:

Module petlib.ec
----------------

.. autoclass:: petlib.ec.EcGroup
    :members:

.. autoclass:: petlib.ec.EcPt
    :members:

Module petlib.cipher
--------------------

.. autoclass:: petlib.cipher.Cipher
    :members:

.. autoclass:: petlib.cipher.CipherOperation
    :members:

Module petlib.hmac
----------------

.. autoclass:: petlib.hmac.Hmac
    :members:

.. autofunction:: petlib.hmac.secure_compare

Module petlib.ecdsa
-------------------

.. autofunction:: petlib.ecdsa.do_ecdsa_sign

.. autofunction:: petlib.ecdsa.do_ecdsa_verify


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

License
=======

Petlib is licensed under the following terms:

Copyright (c) 2014, George Danezis (UCL)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.