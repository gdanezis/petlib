.. petlib documentation master file, created by
   sphinx-quickstart on Sun Nov 23 00:41:16 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to petlib's documentation!
==================================

Testing and Packaging:
----------------------

Petlib uses `py.test`_ for managing and running unit tests, and the `pytest-cov`_ module for test coverage. For running all tests and generating a code coverage report run::

	py.test --cov petlib petlib/*.py

.. _py.test: http://pytest.org
.. _pytest-cov: https://pypi.python.org/pypi/pytest-cov

To generate an HTML report of lines not covered by tests run::

	py.test --cov-report html --cov petlib petlib/*.py


Contents:
---------

.. toctree::
   :maxdepth: 2

.. automodule:: petlib
 
.. autoclass:: petlib.bn.Bn
    :members:

.. autoclass:: petlib.ec.EcGroup
    :members:

.. autoclass:: petlib.ec.EcPt
    :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

