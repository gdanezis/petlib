petlib
======

A python library that implements a number of Privacy Enhancing Technologies (PETs). 

* The full petlib documentation: http://petlib.readthedocs.org/en/latest/
* Package petlib on pypi: https://pypi.python.org/pypi/petlib/
* Git repository: https://github.com/gdanezis/petlib
* Travis CI report: https://travis-ci.org/gdanezis/petlib

.. docs-include-marker-begin-do-not-remove

Pre-requisites
--------------

On *Ubuntu / debian* use `apt-get` to install package ``libssl-dev``. Ensure you also install ``libffi-dev`` and ``python-dev``::

	sudo apt-get install python-dev
	sudo apt-get install libssl-dev
	sudo apt-get install libffi-dev

On *MacOS*, install OpenSSL 1.1.x using homebrew:
    
    brew install openssl@1.1

On *Windows*, install 32 bit or 64 bit OpenSSL binary edition matching your Python installation. Ensure ``libeay32.dll`` is on the system ``PATH`` (https://www.openssl.org/related/binaries.html).
Configure the path variables of Microsoft VS compilers for 32 bit or 64 bit architectures, by executing the command ``vcvars32.bat`` or ``vcvarsx86_amd64.bat``.
 

Quick install
-------------

If you have ``pip`` installed the following command should install ``petlib``::

	pip install petlib

Test your installation::

	python -c "import petlib; petlib.run_tests()"


.. docs-include-marker-end-do-not-remove

Build & Test
------------

You may use ``setuptools`` and ``tox`` to build and test the library::

	python setup.py build_ext

To run all tests simply do::

	tox
