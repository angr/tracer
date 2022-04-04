import os
import tracer
import unittest

from angr.state_plugins.trace_additions import ZenPlugin

import logging
l = logging.getLogger("tracer.tests.test_cache_stall")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

unittest.skip("broken")
def broken_cache_stall():
    # test a valid palindrome
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/CROMU_00071"), bytes.fromhex("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c"))
    ZenPlugin.prep_tracer(t.simgr.one_active)
    crash_path, crash_state = t.run()

    assert crash_path is not  None
    assert crash_state is not None

    # load it again
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/CROMU_00071"), bytes.fromhex("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c"))
    ZenPlugin.prep_tracer(t.simgr.one_active)
    crash_path, crash_state = t.run()

    assert crash_path is not None
    assert crash_state is not None

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("tracer").setLevel("DEBUG")

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
