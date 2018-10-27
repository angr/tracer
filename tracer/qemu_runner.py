import subprocess
import contextlib
import resource
import tempfile
import logging
import shutil
import signal
import socket
import time
import os
import re

l = logging.getLogger("tracer.qemu_runner")

import angr
from .tracerpov import TracerPoV
from .tinycore import TinyCore
from .runner import Runner, RunnerEnvironmentError

try:
    import shellphish_qemu
except ImportError as e:
    raise ImportError("Unable to import shellphish_qemu, which is required by QEMURunner. Please install it before proceeding.") from e


class QEMURunner(Runner):
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
        :param binary        : Path to the binary to be traced.
        :param input         : Concrete input to feed to binary (string or CGC TracerPoV).
        :param project       : The original project.
        :param record_trace  : Whether or not to record the basic block trace.
        :param record_stdout : Whether ot not to record the output of tracing process.
        :param record_magic  : Whether ot not to record the magic flag page as reported by QEMU.
        :param record_core   : Whether or not to record the core file in case of crash.
        :param report_bad_args: Enable CGC QEMU's report bad args option.
        :param use_tiny_core : Use minimal core loading.
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

        Runner.__init__(self, binary=binary, input=input, project=project, record_trace=record_trace,
                        record_core=record_core, use_tiny_core=use_tiny_core, trace_source_path=qemu, argv=argv)

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

        self.input_max_size = max_size or len(input) if input is not None else None

        self.trace_log_limit = trace_log_limit
        self.trace_timeout = trace_timeout
        self._setup()

        l.debug("Accumulating basic block trace...")
        l.debug("tracer qemu path: %s", self._trace_source_path)

        self.stdout = None

        # We need this to keep symbolic traces following the same path
        # as their dynamic counterpart
        self.magic = None

        if exec_func:
            self._exec_func = exec_func

        if record_stdout:
            tmp = tempfile.mktemp(prefix="stdout_" + os.path.basename(self._p.filename))
            # will set crash_mode correctly
            self._run(stdout_file=tmp)
            with open(tmp, "rb") as f:
                self.stdout = f.read()
            os.remove(tmp)
        else:
            # will set crash_mode correctly
            self._run()


### SETUP

    @staticmethod
    def _memory_limit_to_int(ms):
        if not isinstance(ms, str):
            raise ValueError("memory_limit must be a string such as \"8G\"")

        if ms.endswith('k'):
            return int(ms[:-1]) * 1024
        elif ms.endswith('M'):
            return int(ms[:-1]) * 1024 * 1024
        elif ms.endswith('G'):
            return int(ms[:-1]) * 1024 * 1024 * 1024

        raise ValueError("Unrecognized size, should be 'k', 'M', or 'G'")

    def _setup(self):
        # check the binary
        for binary in self._binaries:
            if not os.access(binary, os.X_OK):
                if os.path.isfile(binary):
                    error_msg = "\"%s\" binary is not executable" % binary
                    l.error(error_msg)
                    raise RunnerEnvironmentError(error_msg)
                else:
                    error_msg = "\"%s\" binary does not exist" % binary
                    l.error(error_msg)
                    raise RunnerEnvironmentError(error_msg)

        # hack for the OS
        if self.os != 'cgc' and not self.os.startswith("UNIX"):
            error_msg = "\"%s\" runs on an OS not supported by the qemu runner (only cgc and elf at the moment)" % self._binaries[0]
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

    # create a tmp dir in /dev/shm, chdir into it, set rlimit, save the current self.binary
    # at the end, it restores everything
    @contextlib.contextmanager
    def _setup_env(self):
        prefix = "/tmp/tracer_"
        curdir = os.getcwd()
        tmpdir = tempfile.mkdtemp(prefix=prefix)
        # allow cores to be dumped
        saved_limit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        binaries_old = [ ]
        for binary in self._binaries:
            binaries_old.append(binary)

        binary_replacements = [ ]
        for i, binary in enumerate(self._binaries):
            binary_replacements.append(os.path.join(tmpdir,"binary_replacement_%d" % i))

        for binary_o, binary_r in zip(binaries_old, binary_replacements):
            shutil.copy(binary_o, binary_r)

        self._binaries = binary_replacements
        if self.argv is not None:
            self.argv = self._binaries + self.argv[1:]
        os.chdir(tmpdir)
        try:
            yield (tmpdir,binary_replacements)
        finally:
            assert tmpdir.startswith(prefix)
            shutil.rmtree(tmpdir)
            os.chdir(curdir)
            resource.setrlimit(resource.RLIMIT_CORE, saved_limit)
            self._binaries = binaries_old

    def _run(self, stdout_file=None):
        with self._setup_env() as (_,binary_replacement_fname):
            # get the dynamic trace
            self._run_trace(stdout_file=stdout_file)

            if self.crash_mode and self._record_core:
                # find core file
                binary_common_prefix = "_".join(os.path.basename(binary_replacement_fname[0]).split("_")[:2])
                unique_prefix = "qemu_{}".format(os.path.basename(binary_common_prefix))
                core_files = [x for x in os.listdir('.') if x.startswith(unique_prefix) and x.endswith('.core')]

                a_mesg = "No core files found for binary, this shouldn't happen"
                assert len(core_files) > 0, a_mesg
                a_mesg = "Multiple core files found for binary, this shouldn't happen"
                assert len(core_files) < 2, a_mesg
                core_file = core_files[0]

                # get crashed binary
                self.crashed_binary = int(core_file.split("_")[3])

                a_mesg = "Empty core file generated"
                assert os.path.getsize(core_file) > 0, a_mesg

                if self._use_tiny_core:
                    self._load_tiny_core(core_file)
                else:
                    self._load_core_values(core_file)

    def __get_rlimit_func(self):
        def set_fsize():
            # here we limit the logsize
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (self.trace_log_limit, self.trace_log_limit))

        return set_fsize

    def _exec_func(self, args, stdin=None, stdout=None, stderr=None, tracefile=None, magicfile=None): #pylint:disable=method-hidden,unused-argument
        #pylint:disable=subprocess-popen-preexec-fn
        r = { }
        r['process'] = subprocess.Popen(
            args,
            stdin=stdin, stdout=stdout, stderr=stderr,
            preexec_fn=self.__get_rlimit_func()
        )
        return r

    def _run_trace(self, stdout_file=None):
        logname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        args = [self._trace_source_path]

        if self._bitflip:
            args.append("-bitflip")

        if self._seed is not None:
            args.append("-seed")
            args.append(str(self._seed))

        # If the binary is CGC we'll also take this opportunity to read in the
        # magic page.
        if self._record_magic:
            mname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-magic-")
            args += ["-magicdump", mname]
        else:
            mname = None

        if self._record_trace:
            args += ["-d", "exec", "-D", logname]
        else:
            args += ["-enable_double_empty_exiting"]

        if self._report_bad_args:
            args += ["-report_bad_args"]

        if 'cgc' not in self._trace_source_path:
            args += ['-E', 'LD_BIND_NOW=1']

        if self._library_path:
            args += ['-E', 'LD_LIBRARY_PATH=' + ':'.join(self._library_path)]

        # Memory limit option is only available in shellphish-qemu-cgc-*
        if 'cgc' in self._trace_source_path:
            args += ["-m", self._memory_limit]

        if self._ld_linux:
            args.append(self._ld_linux)

        args += self.argv or [self._binaries[0]]

        stdout_f = subprocess.DEVNULL
        if stdout_file is not None:
            stdout_f = open(stdout_file, 'wb')

        p = None
        try:
            # we assume qemu with always exit and won't block
            if type(self.input) is bytes:
                l.debug("Tracing as raw input")
                l.debug(" ".join(args))
                exec_details = self._exec_func(
                    args,
                    stdin=subprocess.PIPE, stdout=stdout_f, stderr=subprocess.DEVNULL,
                )
                p = exec_details['process']
                p.communicate(self.input, timeout=self.trace_timeout)
            else:
                l.debug("Tracing as pov file")
                in_s, out_s = socket.socketpair()
                exec_details = self._exec_func(
                    args,
                    stdin=in_s, stdout=stdout_f, stderr=subprocess.DEVNULL,
                )
                p = exec_details['process']

                for write in self.input.writes:
                    out_s.send(write)
                    time.sleep(.01)

            ret = p.wait(timeout=self.trace_timeout)

            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("Input caused a crash (signal %d) during dynamic tracing", abs(ret))
                    l.debug(repr(self.input))
                    l.debug("Crash mode is set")
                    self.crash_mode = True

        except subprocess.TimeoutExpired:
            if p is not None:
                p.terminate()
                self.tmout = True

        self.returncode = p.returncode

        if stdout_file is not None:
            stdout_f.close()

        if self._record_trace:
            try:
                trace = open(logname, 'rb').read()
                addrs = []

                # Find where qemu loaded the binary. Primarily for PIE
                qemu_base_addr = int(trace.split(b"start_code")[1].split(b"\n")[0], 16)
                if self.base_addr != qemu_base_addr and self._p.loader.main_object.pic:
                    self.base_addr = qemu_base_addr
                    self.rebase = True

                prog = re.compile(br'Trace (.*) \[(?P<addr>.*)\].*')
                for t in trace.split(b'\n'):
                    m = prog.match(t)
                    if m is not None:
                        addr_str = m.group('addr')
                        addrs.append(int(addr_str, base=16))
                    else:
                        continue

                # grab the faulting address
                if self.crash_mode:
                    self.crash_addr = int(trace.split(b'\n')[-2].split(b'[')[1].split(b']')[0], 16)


                self.trace = addrs
                l.debug("Trace consists of %d basic blocks", len(self.trace))
            except IndexError:
                l.warning("The trace is found to be malformed. "
                "it is possible that the log file size exceeds the 1G limit, "
                "meaning that there might be infinite loops in the target program.")
            finally:
                os.remove(logname)

        if mname is not None:  # if self._record_magic:
            try:
                self.magic = open(mname, 'rb').read()
                a_mesg = "Magic content read from QEMU improper size, should be a page in length"
                assert len(self.magic) == 0x1000, a_mesg
            except IOError:
                pass
            finally:
                try:
                    os.remove(mname)
                except OSError:
                    pass

    def _load_core_values(self, core_file):
        p = angr.Project(core_file)
        self.reg_vals = {reg:val for (reg, val) in p.loader.main_object.initial_register_values()}
        self._state = p.factory.entry_state()
        self.memory = self._state.memory

    def _load_tiny_core(self, core_file):
        tc = TinyCore(core_file)
        self.reg_vals = tc.registers
        self.memory = None
