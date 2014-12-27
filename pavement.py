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
    sh('py.test --doctest-modules --cov-report html --cov petlib petlib/*.py')


@task
def build():
    tell("Build dist")
    sh('python setup.py sdist')


@task
def make_docs():
    tell("Making Docs")
    with pushd('docs') as old_dir:
        sh('make html')


def get_latest_dist():
    D = sh("grep version=\"*\" setup.py", capture = True)
    v = re.findall("version=['\"](.*)['\"]", D)[0]
    return os.path.join("dist","petlib-%s.tar.gz" % v)


@needs('build')
@task
def make_env():
    if os.path.exists("test_env"):
        return
    os.mkdir("test_env")
    with pushd('test_env') as old_dir:
        sh("virtualenv pltest")


@needs("make_env")
@task
@virtualenv(dir=r"test_env/pltest")
def big_tests():
    sh("pip install %s" % get_latest_dist())
    sh("py.test examples/*.py")
    

@needs('unit_tests', 'big_tests')
@task
def test():
    pass


@needs('unit_tests', 'build', 'make_docs', 'make_env', 'big_tests')
@task
def default():
    pass