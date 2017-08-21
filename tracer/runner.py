import os
import logging

import angr

l = logging.getLogger("tracer.Runner")

class Runner(object):
    """
    Base class of trace sources for angr Tracer exploration technique. A
    trace source traces an angr path with a concrete input.
    """

    def __init__(self, project=None, binary=None, input=None, record_trace=False,
                 record_core=False, use_tiny_core=False, trace_source_path=None):
        """
        :param project: the original project.
        :param binary: path to the binary to be traced.
        :param input: concrete input string to feed to binary.
        :param record_trace: whether or not to record the basic block trace.
        :param record_core: whether or not to record the core file in case of crash.
        :param use_tiny_core: Use minimal core loading.
        :param trace_source_path: path to the trace source to be used.
        """
        if project is None and binary is None:
            raise ValueError("Must specify project or binary.")

        self.is_multicb = False

        if project is None:
            if isinstance(binary, basestring):
                self.binaries = [binary]
            elif isinstance(binary, (list, tuple)):
                if not multicb_available:
                    raise ValueError("Multicb tracing is disabled")
                self.is_multicb = True
                self.binaries = binary
            else:
                raise ValueError("Expected list or string for binary, got {} instead".format(type(binary)))
            self._p = angr.Project(self.binaries[0])
        else:
            self._p = project
            self.binaries = [project.filename]

        # Hack for architecture and OS.
        self.os = self._p.loader.main_object.os
        self.base_addr = self._p.loader.main_object.min_addr

        self.input = input
        self._record_trace = record_trace
        self._record_core = record_core

        # Basic block trace.
        self.trace = [ ]

        # In case of crash and record_core is set.
        self.crashed_binary = 0
        self.reg_vals = None
        self._state = None
        self.memory = None
        self.use_tiny_core = use_tiny_core

        # Is a PoV provided?
        self.pov = False

        self.trace_source = None
        self.trace_source_path = trace_source_path

        # Does the input cause a crash?
        self.crash_mode = False
        # If the input causes a crash, what address does it crash at?
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

    def _run(self, stdout_file=None):
        """
        Accumulate a basic block trace.
        """
        raise NotImplementedError('_run() is not implemented.')
