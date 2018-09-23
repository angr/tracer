import os
import nose
import angr
import logging

from tracer import QEMURunner

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_runner():
    r = QEMURunner(binary=os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), input=b"racecar\n")
    nose.tools.assert_equal(r.crash_mode, False)

    r = QEMURunner(binary=os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), input=b"A" * 129)
    nose.tools.assert_equal(r.crash_mode, True)

    binary_path = os.path.join(bin_location, "tests/cgc/CROMU_00070")
    p = angr.Project(binary_path)
    r = QEMURunner(project=p, input=b"hello")
    nose.tools.assert_equal(r.crash_mode, False)

    r = QEMURunner(project=p, input=b"\x00" * 20)
    nose.tools.assert_equal(r.crash_mode, False)

    r = QEMURunner(binary=os.path.join(bin_location, "tests/i386/call_symbolic"), input=b"A" * 700)
    nose.tools.assert_equal(r.crash_mode, True)

    r = QEMURunner(binary=os.path.join(bin_location, "tests/cgc/CROMU_00071"),
                   input=bytes.fromhex("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c"))
    nose.tools.assert_equal(r.crash_mode, True)

    blob = bytes.fromhex("00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611")
    r = QEMURunner(binary=os.path.join(os.path.dirname(__file__), "../../binaries/tests/cgc/NRFIN_00075"), input=blob)
    nose.tools.assert_equal(r.crash_mode, True)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger('tracer.qemu_runner').setLevel('DEBUG')

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
