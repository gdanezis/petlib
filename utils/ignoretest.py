## Usage: 
# export PYTHONPATH=`pwd`:$PYTHONPATH
# pylint --load-plugins ignoretest examples/kulan.py 

from astroid import MANAGER
from astroid import scoped_nodes

def register(linter):
  pass

def transform(modu):
    for m in list(modu):
        try:
            if m.startswith("test_") and modu[m].is_function:
                print("Ignore function: %s" % m)
                modu.body.remove(modu[m])
        except:
            continue

MANAGER.register_transform(scoped_nodes.Module, transform)