import os
import tracer
import logging
import nose

def test_recursion():
    blob = "00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611".decode('hex')
    t = tracer.Tracer(os.path.join(
        os.path.dirname(__file__),
        "../../binaries/tests/cgc/NRFIN_00075"
    ), blob)
    _, crash_state = t.run()
    nose.tools.assert_true(crash_state.se.symbolic(crash_state.regs.ip))

if __name__ == '__main__':
    logging.getLogger("tracer").setLevel("DEBUG")
    test_recursion()
