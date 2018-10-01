.. petlib documentation master file, created by
   sphinx-quickstart on Sun Nov 23 00:41:16 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to petlib's documentation!
==================================

.. image:: https://travis-ci.org/gdanezis/petlib.svg?branch=master
    :target: https://travis-ci.org/gdanezis/petlib

.. image:: https://readthedocs.org/projects/petlib/badge/?version=latest
    :target: https://readthedocs.org/projects/petlib/?badge=latest
    :alt: Documentation Status

.. include:: ../README.rst 
   :start-after: docs-include-marker-begin-do-not-remove
   :end-before: docs-include-marker-end-do-not-remove

Testing and Packaging
---------------------

You will need a working Python 2.7 and 3.6 environemnt with pytest::

  sudo apt-get install python-pytest
  sudo apt-get install python3-pytest
  sudo apt-get install python-sphinx
  sudo pip install Mock

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

petlib Introduction & Examples
------------------------------

The ``petlib`` library is designed as a one-stop-shop library to prototype advanced Privacy Enhancing Technologies (PETs) in Python. It abstracts a number of OpenSSL APIs supporting operations on
big numbers (bn), elliptic curves (ec), ciphers such as AES in a variety of modes of operation (CTM, GCM, ...) (ciphers), message authentication codes (hmac) and ECDSA signatures (ecdsa). 

Besides ``petlib`` Python offers a number of modules in the standard library that are necessary to support modern cryptography:

  * The ``hashlib`` module offers cryptographic hash functions such as ``sha256``, and ``sha512``.
  * The ``os`` module offers the ``urandom`` cryptographically strong random number generator.
  * The ``hmac`` module offers keyed hash-based message authentication codes as well as facilities for constant time comparison.

Examples of use of ``petlib`` for implementing historical as well as state of the art PETs include:
  * A `toy raw-RSA`_ implementation, illustrates the use of ``petlib.bn``.
  * An `additively homomorphic encryption system (AHEG)`_ based on EC El-Gamal, illustrating the use of ``petlib.ec``.
  * A `Schnorr zero-knowledge proof`_ of knowledge or a discrete logarithm in EC groups.
  * An `engine to prove and verify in zero-knowledge statements about Discrete Logarithm representations`_ in EC groups. This is a building blocks for a number of advanced protocols.
  * The `algebraic message authentication code`_ scheme by Chase, Meiklejohn and Zaverucha (ACM CCS 2014). Illustrates how the generic proof framework of ``genzkp.py`` may be used to easily construct zero-knowledge proofs.
  * A reference implementation of the `Anonymous Credentials Light`_ scheme by Baldimtsi, Foteini, and Anna Lysyanskaya (ACM CCS 2013).

.. _toy raw-RSA: https://github.com/gdanezis/petlib/blob/master/examples/toyrsa.py
.. _additively homomorphic encryption system (AHEG): https://github.com/gdanezis/petlib/blob/master/examples/AHEG.py
.. _Schnorr zero-knowledge proof: https://github.com/gdanezis/petlib/blob/master/examples/zkp.py
.. _engine to prove and verify in zero-knowledge statements about Discrete Logarithm representations: https://github.com/gdanezis/petlib/blob/master/examples/genzkp.py
.. _algebraic message authentication code: https://github.com/gdanezis/petlib/blob/master/examples/genzkp.py
.. _Anonymous Credentials Light: https://github.com/gdanezis/petlib/blob/master/examples/BLcred.py


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
------------------

.. autoclass:: petlib.hmac.Hmac
    :members:

.. autofunction:: petlib.hmac.secure_compare

Module petlib.ecdsa
-------------------

.. automodule:: petlib.ecdsa

.. autofunction:: petlib.ecdsa.do_ecdsa_setup

.. autofunction:: petlib.ecdsa.do_ecdsa_sign

.. autofunction:: petlib.ecdsa.do_ecdsa_verify

Module petlib.pack
------------------

.. automodule:: petlib.pack

.. autofunction:: petlib.pack.encode

.. autofunction:: petlib.pack.decode



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
