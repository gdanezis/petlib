petlib
======

A python library that implements a number of Privacy Enhancing Technologies (PETs)


Pre-requisites
--------------

* On Ubuntu / debian use `apt-get` to install package `libssl-dev`.

* On MacOS, install OpenSSL 1.0.2 in `/opt/local`.

* On Windows, install 32 bit or 64 bit OpenSSL binary edition matching your Python installation. Ensure `libeay32.dll` is on the system `PATH` (https://www.openssl.org/related/binaries.html).
Configure the path variables of Microsoft VS compilers for 32 bit or 64 bit architectures, by executing the command `vcvars32.bat` or `vcvarsx86_amd64.bat`.
 

Quick install
-------------

If you have `pip` installed the following command should install `petlib`

	pip install petlib

Test your installation:

	python -c "import petlib; petlib.run_tests()"


Build
-----

1. Install paver (http://paver.github.io/paver/).

2. Install pytest (http://pytest.org/latest/).

3. Install pytest-cov (https://pypi.python.org/pypi/pytest-cov).

4. Run paver.
