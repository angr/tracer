import subprocess
import contextlib
import resource
import tempfile
import logging
import signal
import socket
import shutil
import time
import glob
import os
import re

l = logging.getLogger("tracer.qemu_runner")

import angr
from .tracerpov import TracerPoV
from .tinycore import TinyCore

try:
    import shellphish_qemu
except ImportError as e:
    raise ImportError("Unable to import shellphish_qemu, which is required by QEMURunner. Please install it before proceeding.") from e

class RunnerEnvironmentError(Exception):
    pass

class QEMURunner:
    """
    Trace an angr path with a concrete input using QEMU.
    """

    def __init__(
        self, binary=None, input=None, project=None, record_trace=True, record_stdout=False,
        record_magic=True, record_core=False, seed=None, memory_limit="8G", bitflip=False, report_bad_args=False,
        use_tiny_core=False, max_size=None, qemu=None, argv=None, library_path=None, ld_linux=None,
        trace_log_limit=2**30, trace_timeout=10, exec_func=None
    ): #pylint:disable=redefined-builtin
        """
        :param argv             : Optionally specify argv params (i,e,: ['./calc', 'parm1']).
        :param binary        : Path to the binary to be traced.
        :param input         : Concrete input to feed to binary (bytes or CGC TracerPoV).
        :param project       : The original project.
        :param record_trace  : Whether or not to record the basic block trace.
        :param record_stdout : Whether ot not to record the output of tracing process.
        :param record_magic  : Whether ot not to record the magic flag page as reported by QEMU.
        :param record_core   : Whether or not to record the core file in case of crash.
        :param report_bad_args: Enable CGC QEMU's report bad args option.
        :param use_tiny_core : Use minimal core loading.
        :param trace_source_path: Path to the trace source to be used.
                                  Defaults to binary name with no params.
        :param max_size      : Optionally set max size of input. Defaults to size
                               of preconstrained input.
        :param qemu          : Path to QEMU to be forced used.
        :param argv          : Optionally specify argv params (i,e,: ['./calc', 'parm1']).
                               Defaults to binary name with no params.
        :param trace_log_limit: Optionally specify the dynamic trace log file
            size limit in bytes, defaults to 1G.
        :param trace_timeout : Optionally specify the dymamic time limit in seconds
            defaults to 10 seconds.
        :param exec_func     : Optional function to run instead of self._exec_func.
        """


        if type(input) not in (bytes, TracerPoV):
            raise RunnerEnvironmentError("Input for tracing should be either a bytestring or a TracerPoV for CGC PoV file.")

        if binary is not None:
            self._filename = binary
            self._p = angr.Project(self._filename)
        elif project is not None:
            self._p = project
            self._filename = project.filename
        else:
            raise ValueError("Must specify project or binary.")

        # Hack for architecture and OS.
        self.os = self._p.loader.main_object.os
        self.base_addr = self._p.loader.main_object.min_addr
        self.rebase = False

        self.input = input

        self._record_trace = record_trace
        self._record_core = record_core

        self.argv = argv

        # Basic block trace.
        self.trace = [ ]

        # In case of crash and record_core is set.
        self.reg_vals = None
        self._state = None
        self.memory = None
        self._use_tiny_core = use_tiny_core

        self.trace_source = None
        self._trace_source_path = qemu

        # Does the input cause a crash?
        self.crash_mode = False
        # If the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.stdout = None

        # compatibility for now
        self.is_multicb = False

        self.tmout = False
        self.returncode = None
        self._record_magic = record_magic and self.os == 'cgc'

        if type(library_path) is str:
            library_path = [library_path]
        self._library_path = library_path
        self._ld_linux = ld_linux

        if isinstance(seed, int):
            seed = str(seed)
        self._seed = seed
        self._memory_limit = memory_limit
        self._bitflip = bitflip

        self._report_bad_args = report_bad_args

        if self.input is None:
            raise ValueError("Must specify input.")

        # validate seed
        if self._seed is not None:
            try:
                iseed = int(self._seed)
                if iseed > 4294967295 or iseed < 0:
                    raise ValueError
            except ValueError:
                raise ValueError("The passed seed is either not an integer or is not between 0 and UINT_MAX")

        self.input_max_size = max_size or len(input) if type(input) is bytes else None

        self.trace_log_limit = trace_log_limit
        self.trace_timeout = trace_timeout
        self.sanity_check()

        l.debug("Accumulating basic block trace...")
        l.debug("tracer qemu path: %s", self._trace_source_path)

        self.stdout = None

        # We need this to keep symbolic traces following the same path
        # as their dynamic counterpart
        self.magic = None

        if exec_func:
            self._exec_func = exec_func

        if record_stdout:
            fd, tmp = tempfile.mkstemp(prefix="stdout_" + os.path.basename(self._p.filename))
            # will set crash_mode correctly
            self._run(stdout_file=tmp)
            with open(tmp, "rb") as f:
                self.stdout = f.read()
            os.close(fd)
            os.remove(tmp)
        else:
            # will set crash_mode correctly
            self._run()


### SETUP

    def sanity_check(self):
        self._check_binary()
        self._check_qemu_install()

    def _check_binary(self):
        # check the binary
        if not os.access(self._filename, os.X_OK):
            if os.path.isfile(self._filename):
                error_msg = "\"%s\" binary is not executable" % self._filename
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)
            else:
                error_msg = "\"%s\" binary does not exist" % self._filename
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)

        # hack for the OS
        if self.os != 'cgc' and not self.os.startswith("UNIX"):
            error_msg = "\"%s\" runs on an OS not supported by the qemu runner (only cgc and elf at the moment)" % self._filename
            l.error(error_msg)
            raise RunnerEnvironmentError(error_msg)

        # try to find the install base
        self._check_qemu_install()

    def _check_qemu_install(self):
        """
        Check the install location of QEMU.
        """
        if self.os == "cgc":
            suffix = "tracer" if self._record_trace else "base"
            self.trace_source = "shellphish-qemu-cgc-%s" % suffix
        else:
            self.trace_source = "shellphish-qemu-linux-%s" % self._p.arch.qemu_name

        if self._trace_source_path is None or not os.access(self._trace_source_path, os.X_OK):
            if self._trace_source_path is not None:
                l.warning("Problem accessing forced %s. Using our default %s.", self._trace_source_path, self.trace_source)

            self._trace_source_path = shellphish_qemu.qemu_path(self.trace_source)

            if not os.access(self._trace_source_path, os.X_OK):
                if os.path.isfile(self._trace_source_path):
                    error_msg = "%s is not executable" % self.trace_source
                    l.error(error_msg)
                    raise RunnerEnvironmentError(error_msg)
                else:
                    error_msg = "\"%s\" does not exist" % self._trace_source_path
                    l.error(error_msg)
                    raise RunnerEnvironmentError(error_msg)

### DYNAMIC TRACING

    def __get_rlimit_func(self):
        def set_rlimits():
            # here we limit the logsize
            resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
            resource.setrlimit(resource.RLIMIT_FSIZE, (self.trace_log_limit, self.trace_log_limit))

        return set_rlimits

    @staticmethod
    @contextlib.contextmanager
    def _mk_tmpdir():
        tmpdir = tempfile.mkdtemp(prefix="/tmp/tracer_")
        try:
            yield tmpdir
        finally:
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(tmpdir)

    @staticmethod
    @contextlib.contextmanager
    def _tmpfile(**kwargs):
        fd, tmpfile = tempfile.mkstemp(**kwargs)
        os.close(fd)
        try:
            yield tmpfile
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmpfile)

    @contextlib.contextmanager
    def _exec_func(self, qemu_variant, qemu_args, program_args, ld_path=None, stdin=None, stdout=None, stderr=None, record_trace=True, record_magic=False, core_target=None): #pylint:disable=method-hidden
        #pylint:disable=subprocess-popen-preexec-fn

        with self._mk_tmpdir() as tmpdir, self._tmpfile(dir="/dev/shm/", prefix="tracer-log-") as trace_filename, self._tmpfile(dir="/dev/shm/", prefix="tracer-magic-") as magic_filename, contextlib.ExitStack() as exit_stack:
            cmd_args = [ qemu_variant ]
            cmd_args += qemu_args
            cmd_args += ["-C", tmpdir]

            # hardcode an argv[0]
            #cmd_args += [ "-0", program_args[0] ]

            # record the trace, if we want to
            if record_trace:
                if 'cgc' in qemu_variant:
                    cmd_args += ["-d", "exec", "-D", trace_filename]
                else:
                    cmd_args += ["-d", "exec,nochain,page", "-D", trace_filename]
            else:
                trace_filename = None
                cmd_args += ["-enable_double_empty_exiting"]

            # If the binary is CGC we'll also take this opportunity to read in the magic page.
            if record_magic:
                cmd_args += ["-magicdump", magic_filename]
            else:
                magic_filename = None

            if ld_path:
                cmd_args.append(ld_path)

            # and the program
            cmd_args += program_args

            # set up files
            stdin_file = subprocess.DEVNULL if stdin is None else exit_stack.enter_context(open(stdin, 'wb')) if type(stdin) is str else stdin
            stdout_file = subprocess.DEVNULL if stdout is None else exit_stack.enter_context(open(stdout, 'wb')) if type(stdout) is str else stdout
            stderr_file = subprocess.DEVNULL if stderr is None else exit_stack.enter_context(open(stderr, 'wb')) if type(stderr) is str else stderr

            r = { }
            r['process'] = subprocess.Popen(
                cmd_args,
                stdin=stdin_file, stdout=stdout_file, stderr=stderr_file,
                preexec_fn=self.__get_rlimit_func()
            )

            try:
                yield r
                r['returncode'] = r['process'].wait(timeout=self.trace_timeout)
                r['timeout'] = False

                # save the trace
                r['trace'] = ''
                if record_trace:
                    with open(trace_filename, 'rb') as tf:
                        r['trace'] = tf.read()

                # save the magic
                r['magic'] = ''
                if record_magic:
                    with open(magic_filename, 'rb') as tf:
                        r['magic'] = tf.read()

                # save the core and clean up the original core
                core_glob = glob.glob(os.path.join(tmpdir, "qemu_"+os.path.basename(program_args[0])+"_*.core"))

                if core_target and core_glob:
                    shutil.copy(core_glob[0], core_target)
                if core_glob:
                    os.unlink(core_glob[0])

            except subprocess.TimeoutExpired:
                r['process'].terminate()
                r['returncode'] = r['process'].wait()
                if record_trace and 'trace' not in r:
                    r['trace'] = b''
                if record_magic and 'magic' not in r:
                    r['magic'] = b''
                r['timeout'] = True

        return r

    def _run(self, stdout_file=None):
        qemu_variant = self._trace_source_path
        qemu_args = [ ]

        if self._bitflip:
            qemu_args.append("-bitflip")

        if self._seed is not None:
            qemu_args.append("-seed")
            qemu_args.append(str(self._seed))

        if self._report_bad_args:
            qemu_args += ["-report_bad_args"]

        if 'cgc' not in self._trace_source_path:
            qemu_args += ['-E', 'LD_BIND_NOW=1']

        if self._library_path:
            qemu_args += ['-E', 'LD_LIBRARY_PATH=' + ':'.join(self._library_path)]

        # Memory limit option is only available in shellphish-qemu-cgc-*
        if 'cgc' in self._trace_source_path:
            qemu_args += ["-m", self._memory_limit]

        program_args = self.argv or [self._filename]
        do_pov = type(self.input) is not bytes

        if do_pov:
            l.debug("Tracing as pov file")
            in_s, out_s = socket.socketpair()
        else:
            in_s = subprocess.PIPE
            out_s = None

        with self._tmpfile(prefix='tracer-core-') as core_target:
            with self._exec_func(
                qemu_variant, qemu_args, program_args, ld_path=self._ld_linux,
                stdin=in_s, stdout=stdout_file,
                record_trace=self._record_trace, record_magic=self._record_magic,
                core_target=core_target if self._record_core else None
            ) as exec_details:
                if do_pov:
                    for write in self.input.writes:
                        out_s.send(write)
                        time.sleep(.01)
                else:
                    exec_details['process'].communicate(self.input, timeout=self.trace_timeout)

            self.returncode = exec_details['returncode']
            self.tmout = exec_details['timeout']

            # did a crash occur?
            if self.returncode < 0:
                if abs(self.returncode) == signal.SIGSEGV or abs(self.returncode) == signal.SIGILL:
                    l.info("Input caused a crash (signal %d) during dynamic tracing", abs(self.returncode))
                    l.debug(repr(self.input))
                    l.debug("Crash mode is set")
                    self.crash_mode = True

                if self._record_core:
                    # find core file
                    a_mesg = "Empty core file generated"
                    assert os.path.getsize(core_target) > 0, a_mesg

                    if self._use_tiny_core:
                        self._load_tiny_core(core_target)
                    else:
                        self._load_core_values(core_target)

        if self._record_trace:
            try:
                trace = exec_details['trace']
                addrs = []

                # Find where qemu loaded the binary. Primarily for PIE
                qemu_base_addr = int(trace.split(b"start_code")[1].split(b"\n")[0], 16)
                if self.base_addr != qemu_base_addr and self._p.loader.main_object.pic:
                    self.base_addr = qemu_base_addr
                    self.rebase = True

                prog = re.compile(br'Trace (.*) \[(?P<addr>.*)\].*' if 'cgc' in qemu_variant else br'Trace (.*) \[(?P<something1>.*)\/(?P<addr>.*)\/(?P<flags>.*)\].*')
                for t in trace.split(b'\n'):
                    m = prog.match(t)
                    if m is not None:
                        addr_str = m.group('addr')
                        addrs.append(int(addr_str, base=16))
                    else:
                        continue

                # grab the faulting address
                if self.crash_mode:
                    lastline = trace.split(b'\n')[-2]
                    if lastline.startswith(b"Trace") or lastline.find(b"Segmentation") == -1:
                        l.warning("Trace return code was less than zero, but the last line of the trace does not"
                                  "contain the uncaught exception error from qemu."
                                  "If using an older version of shellphish_qemu try using 'ulimit -Sc 0' or "
                                  "updating to a newer version of shellphish_qemu.")
                    self.crash_addr = int(lastline.split(b'[')[1].split(b']')[0], 16)


                self.trace = addrs
                l.debug("Trace consists of %d basic blocks", len(self.trace))
            except IndexError:
                l.warning("The trace is found to be malformed. "
                "it is possible that the log file size exceeds the 1G limit, "
                "meaning that there might be infinite loops in the target program.")

        if self._record_magic:
            self.magic = exec_details['magic']
            a_mesg = "Magic content read from QEMU improper size, should be a page in length"
            assert len(self.magic) == 0x1000, a_mesg

    def _load_core_values(self, core_file):
        p = angr.Project(core_file)
        self.reg_vals = p.loader.main_object.thread_registers()
        self._state = p.factory.entry_state()
        self.memory = self._state.memory

    def _load_tiny_core(self, core_file):
        tc = TinyCore(core_file)
        self.reg_vals = tc.registers
        self.memory = None
