import os
import logging

l = logging.getLogger("tracer.Runner")

class Runner(object):
    """
    Base class of trace sources for angr Tracer exploration technique. A
    trace source traces an angr path with a concrete input.
    """

    def __init__(self, input=None, record_trace=False, record_core=False, use_tiny_core=False, trace_source_path=None):
        """
        :param input: concrete input string to feed to binary.
        :param record_trace: whether or not to record the basic block trace.
        :param record_core: whether or not to record the core file in case of crash.
        :param use_tiny_core: Use minimal core loading.
        :param trace_source_path: path to the trace source to be used.
        """

        self.input = input
        self._record_trace = record_trace
        self._record_core = record_core

        self.trace = [ ]
        self.crashed_binary = 0
        self.reg_vals = None
        self._state = None
        self.memory = None

        self.use_tiny_core = use_tiny_core

        self.trace_source = None
        self.trace_source_path = trace_source_path

        # does the input cause a crash?
        self.crash_mode = False
        # if the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.stdout = None


### SETUP

    def _setup(self):
        """
        Make sure the environment is sane and we have everything we need to do
        a trace.
        """
        raise NotImplementedError('_setup() is not implemented.')


### DYNAMIC TRACING

    def _dynamic_trace(self, stdout_file=None):
        """
        Accumulate a basic block trace.
        """
        raise NotImplementedError('_dynamic_trace() is not implemented.')
