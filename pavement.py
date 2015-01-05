import os.path
import os
import re

from paver.tasks import task
from paver.easy import sh, needs, pushd
from paver.virtual import *


def tell(x):
    print 
    print "-"*10, x, "-"*10
    print 


@task
def unit_tests():
    tell("Unit tests")
    sh('py.test-2.7 -v --doctest-modules --cov-report html --cov petlib petlib/*.py')

@task
def test3():
    tell("Unit tests for python 3")
    sh('py.test-3.4 -v --doctest-modules --cov-report html --cov petlib petlib/*.py')


@task
def build(quiet=True):
    tell("Build dist")
    sh('python setup.py sdist', capture=quiet)

@task
def upload(quiet=False):
    tell("upload dist")
    sh('python setup.py sdist upload', capture=quiet)

@task
def lintlib(quiet=False):
    tell("Run pylint on the library")
    sh('pylint --rcfile "pylintrc" petlib', capture=quiet)

@needs("make_env")
@task
@virtualenv(dir=r"test_env/pltest")
def lintexamples(quiet=True):
    tell("Run Lint on example code")
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    sh('pylint --rcfile "pylintrc" --load-plugins ignoretest examples/*.py', capture=quiet)

@needs("lintlib", "lintexamples")
@task
def lint():
    pass

@task
def make_docs(quiet=True):
    tell("Making Docs")
    with pushd('docs') as old_dir:
        sh('make html', capture=quiet)


def get_latest_dist():
    D = sh("grep version=\"*\" setup.py", capture = True)
    v = re.findall("version=['\"](.*)['\"]", D)[0]
    return os.path.join("dist","petlib-%s.tar.gz" % v)


@needs('build')
@task
def make_env(quiet=True):
    tell("Make a virtualenv")
    if os.path.exists("test_env"):
        return
    os.mkdir("test_env")
    with pushd('test_env') as old_dir:
        sh("virtualenv pltest", capture=quiet)


@needs("make_env")
@task
@virtualenv(dir=r"test_env/pltest")
def big_tests(quiet=True):
    tell("Run acceptance tests (big examples)")
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    sh("py.test-2.7 -v examples/*.py")
    

@needs('unit_tests', 'big_tests')
@task
def test():
    pass


@needs('unit_tests', 'test3', 'build', 'make_docs', 'make_env', 'big_tests')
@task
def default():
    pass