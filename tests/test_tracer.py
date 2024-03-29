import os
import tracer

import logging

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_cgc_se1_palindrome_raw():
    # Test CGC Scored Event 1's palindrome challenge with raw input
    #import ipdb; ipdb.set_trace()

    # test a valid palindrome
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), b"racecar\n")
    result_state, crash_state = t.run()

    # make sure the heap base is correct and hasn't been altered from the default
    assert result_state.cgc.allocation_base == 0xb8000000

    # make sure there is no crash state
    assert crash_state is None

    # make sure angr modeled the correct output
    stdout_dump = result_state.posix.dumps(1)
    assert stdout_dump.startswith(b"\nWelcome to Palindrome Finder\n\n"
                                                  b"\tPlease enter a possible palindrome: "
                                                  b"\t\tYes, that's a palindrome!\n\n"
                                                  b"\tPlease enter a possible palindrome: ")
    # make sure there were no 'Nope's from non-palindromes
    assert not b"Nope" in stdout_dump

    # now test crashing input
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), b"B" * 129)
    result_state, crash_state = t.run()

    assert result_state is not None
    assert crash_state is not None

def test_symbolic_sized_receives():
    binary_path = os.path.join(bin_location, "tests/cgc/CROMU_00070")
    t = tracer.Tracer(binary_path, b"hello")

    # will except if failed
    result_state, crash_state = t.run()

    assert result_state is not None
    assert crash_state is None

    t = tracer.Tracer(binary_path, b"\x00" * 20)

    # will except if failed
    result_state, crash_state = t.run()

    assert result_state is not None
    assert crash_state is None

def test_allocation_base_continuity():
    correct_out = b'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    t = tracer.Tracer(os.path.join(bin_location, "tests/i386/cgc_allocations"), b"")
    state, _ = t.run()

    assert state.posix.dumps(1) == correct_out

def test_crash_addr_detection():
    t = tracer.Tracer(os.path.join(bin_location, "tests/i386/call_symbolic"), b"A" * 700)
    _, crash_state = t.run()

    assert crash_state.solver.symbolic(crash_state.regs.ip)

def run_all():
    def print_test_name(name):
        print('#' * (len(name) + 8))
        print('###', name, '###')
        print('#' * (len(name) + 8))

    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    l = logging.getLogger("tracer.Tracer").setLevel("DEBUG")

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
