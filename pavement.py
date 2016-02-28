import os.path
import os
import re
import fnmatch


def match_files(directory="petlib", pattern="*.py"):
    files = []
    for file in os.listdir(directory):
        if fnmatch.fnmatch(file, pattern):
            files += [os.path.join(directory, file)]
    return files


from paver.tasks import task, cmdopts
from paver.easy import sh, needs, pushd
from paver.virtual import *


def tell(x):
    print()
    print(("-"*10)+ str(x) + ("-"*10))
    print()


@task
def unit_tests():
    """ Run all the unit tests in a Python 2.7 py.test context, and produce coverage report. """
    tell("Unit tests")
    files = " ".join(match_files())
    sh('python2 petlib/compile.py')
    # sh('py.test-2.7 -v --doctest-modules --cov-report html --cov petlib ' + files)
    sh('py.test-2.7 -v --doctest-modules ' + files)

@task
def generic_unit_tests():
    """ Run all the unit tests in a generic py.test context. """
    tell("Generic Unit tests")
    files = " ".join(match_files())
    sh('python petlib/compile.py')
    # sh('py.test-2.7 -v --doctest-modules --cov-report html --cov petlib ' + files)
    sh('py.test -vs --doctest-modules ' + files)


@task
def test3():
    """ Run all the unit tests in a Python 3.4 py.test context, and produce coverage report. """
    tell("Unit tests for python 3")
    files = " ".join(match_files())
    sh('python3 petlib/compile.py')
    # sh('py.test-3.4 -v --doctest-modules --cov-report html --cov petlib ' + files)
    sh('py.test-3.4 -v --doctest-modules ' + files)

@task
@cmdopts([
    ('file=', 'f', 'File to test.')
])
def testf(options):
    """Test a specific file for Python 2/3 with all flags turned on."""
    tell("Unit tests for specific file")
    print(options)
    sh('py.test-3.4 -vs --doctest-modules --cov %s %s' % (options.file, options.file))
    sh('py.test-2.7 -vs --doctest-modules --cov-report html --cov %s %s' % (options.file, options.file))


@task
def build(quiet=True):
    """ Builds the petlib distribution, ready to be uploaded to pypi. """
    tell("Build dist")
    sh('python setup.py sdist', capture=quiet)

@task
def win(quiet=True):
    """ Builds the petlib binary distribution for windows. """
    tell("Build windows distribution")
    sh('python setup.py build bdist_wininst', capture=quiet)

@task
def upload(quiet=False):
    """ Uploads the latest distribution to pypi. """

    lib = file(os.path.join("petlib", "__init__.py")).read()
    v = re.findall("VERSION.*=.*['\"](.*)['\"]", lib)[0]

    tell("upload dist %s" % v)
    sh('git tag -a v%s -m "Distribution versio v%s"' % (v, v))
    sh('python setup.py sdist upload', capture=quiet)
    tell('Remeber to upload tags using "git push --tags"')

@task
def lintlib(quiet=False):
    """ Run the python linter on petlib with project specific options (see pylintrc petlib). """
    tell("Run pylint on the library")
    sh('pylint --rcfile=pylintrc petlib', capture=quiet)

@needs("lintlib", "lintexamples")
@task
def lint():
    """ Lint all petlib library code and examples. """
    pass

@task
def make_docs(quiet=True):
    """ Build the petlib documentation. """
    tell("Making Docs")
    with pushd('docs') as old_dir:
        sh('make html', capture=quiet)

@task
def wc(quiet=False):
    """ Count the petlib library and example code lines. """
    tell("Counting code lines")

    print("\nLibrary code:")
    sh('wc -l petlib/*.py', capture=quiet)

    print("\nExample code:")
    sh('wc -l examples/*.py', capture=quiet)

    print("\nAdministration code:")
    sh('wc -l pavement.py setup.py docs/conf.py utils/ignoretest.py', capture=quiet)


def get_latest_dist():
    lib = file(os.path.join("petlib", "__init__.py")).read()
    v = re.findall("VERSION.*=.*['\"](.*)['\"]", lib)[0]
    return os.path.join("dist","petlib-%s.tar.gz" % v)


@needs('build')
@task
def make_env(quiet=True):
    """ Build a virtual environment with petlib installed. """
    tell("Make a virtualenv")
    if os.path.exists("test_env"):
        return
    os.mkdir("test_env")
    with pushd('test_env') as old_dir:
        sh("virtualenv pltest", capture=quiet)


@needs("make_env")
@task
@virtualenv(dir=r"test_env/pltest")
def lintexamples(quiet=True):
    """ Run the python linter on the petlib examples. """
    tell("Run Lint on example code")
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    files = " ".join(match_files("examples", "*.py"))
    sh('export PYTHONPATH=$PYHTONPATH:./utils; pylint --rcfile=pylintrc --load-plugins ignoretest ' + files, capture=quiet)


@task
@virtualenv(dir=r"test_env/pltest")
def venv_unit_tests(quiet=False):
    """ Run all the unit tests in a Python 2.7 venv py.test context, and produce coverage report. """
    tell("venv Unit tests")
    files = " ".join(match_files())
    # sh('py.test-2.7 -v --doctest-modules --cov-report html --cov petlib ' + files)
    # sh('py.test-2.7 -v --doctest-modules ' + files)
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    sh("paver unit_tests")


@needs("build", "make_env", "venv_unit_tests")
@task
def venvut(quiet=False):
    pass
    # sh("rm -rf test_env")


@task
@virtualenv(dir=os.path.join(r"test_env",r"pltest"))
def big_tests(quiet=False):
    """ Run all example unit_tests in a fresh python 2.7 context. """
    tell("Run acceptance tests (big examples)")
    # sh("pip install -r requirements.txt", capture=quiet)
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    files = " ".join(match_files("examples", "*.py"))
    sh("py.test-2.7 -v " + files)

@needs("build", "make_env", "big_tests")
@task
def venvbt(quiet=False):
    pass


@task
def local_big_tests(quiet=True):
    """ Run example tests using local install. """
    tell("Run acceptance tests (big examples) using local install.")
    files = " ".join(match_files("examples", "*.py"))
    sh("py.test-2.7 -v " + files)


@needs('unit_tests', 'big_tests')
@task
def test():
    """ Run all tests. """
    pass


@needs('unit_tests', 'test3', 'build', 'make_docs', 'make_env', 'big_tests')
@task
def default():
    """ Run all default tasks to test, and build lib and docs. """
    pass