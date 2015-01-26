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
    print 
    print "-"*10, x, "-"*10
    print 


@task
def unit_tests():
    tell("Unit tests")
    files = " ".join(match_files())
    sh('py.test-2.7 -v --doctest-modules --cov-report html --cov petlib ' + files)

@task
def test3():
    tell("Unit tests for python 3")
    files = " ".join(match_files())
    sh('py.test-3.4 -v --doctest-modules --cov-report html --cov petlib ' + files)

@task
@cmdopts([
    ('file=', 'f', 'File to test.')
])
def testf(options):
    """Test a specific file for Python 2/3 with all flags turned on."""
    tell("Unit tests for specific file")
    print(options)
    sh('py.test-3.4 -v --doctest-modules --cov %s %s' % (options.file, options.file))
    sh('py.test-2.7 -v --doctest-modules --cov %s %s' % (options.file, options.file))


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
    sh('pylint --rcfile=pylintrc petlib', capture=quiet)

@needs("make_env")
@task
@virtualenv(dir=r"test_env/pltest")
def lintexamples(quiet=True):
    tell("Run Lint on example code")
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    files = " ".join(match_files("examples", "*.py"))
    sh('export PYTHONPATH=$PYHTONPATH:./utils; pylint --rcfile=pylintrc --load-plugins ignoretest ' + files, capture=quiet)

@needs("lintlib", "lintexamples")
@task
def lint():
    pass

@task
def make_docs(quiet=True):
    tell("Making Docs")
    with pushd('docs') as old_dir:
        sh('make html', capture=quiet)

@task
def wc(quiet=False):
    tell("Counting code lines")
    sh('wc -l examples/*.py', capture=quiet)
    sh('wc -l petlib/*.py', capture=quiet)

def get_latest_dist():
    D = sh("grep version=\"*\" setup.py", capture = True)
    v = re.findall("version=['\"](.*)['\"]", D)[0]
    return os.path.join("dist","petlib-%s.tar.gz" % v)


@task
@needs('build')
def make_env(quiet=True):
    tell("Make a virtualenv")
    if os.path.exists("test_env"):
        return
    os.mkdir("test_env")
    with pushd('test_env') as old_dir:
        sh("virtualenv pltest", capture=quiet)


@task
@needs("make_env")
@virtualenv(dir=os.path.join(r"test_env",r"pltest"))
def big_tests(quiet=True):
    tell("Run acceptance tests (big examples)")
    sh("pip install %s --upgrade" % get_latest_dist(), capture=quiet)
    files = " ".join(match_files("examples", "*.py"))
    sh("py.test-2.7 -v " + files)

@task
def local_big_tests(quiet=True):
    tell("Run acceptance tests (big examples) using local install.")
    files = " ".join(match_files("examples", "*.py"))
    sh("py.test-2.7 -v " + files)


@needs('unit_tests', 'big_tests')
@task
def test():
    pass


@needs('unit_tests', 'test3', 'build', 'make_docs', 'make_env', 'big_tests')
@task
def default():
    pass