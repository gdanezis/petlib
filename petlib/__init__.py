# The petlib version
VERSION = '0.0.26'

def run_tests():
    # These are only needed in case we test
    import pytest
    import os.path
    import glob

    # List all petlib files in the directory
    petlib_dir = dir = os.path.dirname(os.path.realpath(__file__))
    pyfiles = glob.glob(os.path.join(petlib_dir, '*.py'))
    pyfiles = " ".join(pyfiles)

    # Run the test suite
    print("Directory: %s" % pyfiles)
    res = pytest.main("-v -x %s" % pyfiles)
    print("Result: %s" % res)

    # Return exit result
    return res