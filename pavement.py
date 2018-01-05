import os.path
import os
import re
import fnmatch

from paver.tasks import task, cmdopts
from paver.easy import sh, needs, pushd
from paver.virtual import *


def tell(x):
    print()
    print(("-"*10)+ str(x) + ("-"*10))
    print()

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

    lib = open(os.path.join("petlib", "__init__.py")).read()
    v = re.findall("VERSION.*=.*['\"](.*)['\"]", lib)[0]

    tell("upload dist %s" % v)
    sh('git tag -a v%s -m "Distribution versio v%s"' % (v, v))
    sh('python setup.py sdist upload', capture=quiet)
    tell('Remember to upload tags using "git push --tags"')

@task
def lint(quiet=False):
    """ Run the python linter on petlib with project specific options (see pylintrc petlib). """
    tell("Run pylint on the library")
    sh('pylint --rcfile=pylintrc petlib', capture=quiet)


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

