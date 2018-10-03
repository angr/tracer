import os
import time
import shutil
import signal
import socket
import logging
import resource
import tempfile
import re
import contextlib
import docker

from os import remove, path
import tarfile
from tempfile import NamedTemporaryFile
from base64 import b64decode

from io import BufferedRWPair, DEFAULT_BUFFER_SIZE
l = logging.getLogger("tracer.qemu_runner")

import angr
from .tracerpov import TracerPoV
from .tinycore import TinyCore
from .runner import Runner, RunnerEnvironmentError

try:
    import shellphish_qemu
except ImportError:
    raise ImportError(
        "Unable to import shellphish_qemu, which is required by QEMURunner. Please install it before proceeding.")

try:
    import shellphish_afl

    MULTICB_AVAILABLE = True
except ImportError:
    l.warning("Unable to import shellphish_afl, multicb tracing will be disabled")
    shellphish_afl = None
    MULTICB_AVAILABLE = False


class DockerQEMURunner(Runner):
    """
    Trace an angr path with a concrete input using QEMU.
    """

    def __init__(self, binary=None, input=None, project=None, record_trace=True, record_stdout=False,
                 record_magic=True, record_core=False, seed=None, memory_limit="8G", bitflip=False,
                 report_bad_args=False,
                 use_tiny_core=False, max_size=None, qemu=None, argv=None,
                 trace_log_limit=2 ** 30, trace_timeout=10, container_id=None, image_id=None):
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
        :param trace_timeout  : Optionally specify the dymamic time limit in seconds
            defaults to 10 seconds.
        """
        if type(input) not in (bytes, TracerPoV):
            raise RunnerEnvironmentError(
                "Input for tracing should be either a bytestring or a TracerPoV for CGC PoV file.")

        Runner.__init__(self, binary=binary, input=input, project=project, record_trace=record_trace,
                        record_core=record_core, use_tiny_core=use_tiny_core, trace_source_path=qemu, argv=argv)

        docker_client = docker.from_env()
        if container_id:
            self._container = docker_client.containers.get(container_id)
        elif image_id:
            self._container = docker_client.containers.run(image_id, detach=True, tty=True)
        else:
            raise RunnerEnvironmentError("You need to specify either a container id"
                                         "or a image id")

        self.docker_qemu_base_path = self.get_qemu_base_path()
        self._docker_trace_source_path = None

        self.tmout = False
        self._record_magic = record_magic and self.os == 'cgc'

        if record_trace and self.is_multicb:
            l.warning("record_trace specified with multicb, no trace will be recorded")

        if isinstance(seed, int):
            seed = str(seed)
        self._seed = seed
        self._memory_limit = memory_limit
        self._bitflip = bitflip

        if self._bitflip and self.is_multicb:
            raise ValueError("Cannot perform bitflip with MultiCB")

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
        if self.is_multicb:
            self._fakeforksrv_path = os.path.join(shellphish_afl.afl_dir('multi-cgc'), "run_via_fakeforksrv")

        self._setup()

        l.debug("Accumulating basic block trace...")
        l.debug("tracer qemu path: %s", self._trace_source_path)

        self.stdout = None

        # We need this to keep symbolic traces following the same path
        # as their dynamic counterpart
        self.magic = None

        if record_stdout:
            tmp = tempfile.mktemp(prefix="stdout_" + os.path.basename(binary))
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

        if self.is_multicb:
            if not os.access(self._fakeforksrv_path, os.X_OK):
                error_msg = "fakeforksrv path %s is not executable" % self._fakeforksrv_path
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)

        # hack for the OS
        if self.os != 'cgc' and not self.os.startswith("UNIX"):
            error_msg = "\"%s\" runs on an OS not supported by the qemu runner (only cgc and elf at the moment)" % \
                        self._binaries[0]
            l.error(error_msg)
            raise RunnerEnvironmentError(error_msg)

        # try to find the install base
        self._check_qemu_install()

    def get_qemu_base_path(self):
        _, me = self._container.exec_run('whoami')
        me =  me.decode().strip()

        if'root' == me:
            return '/usr/bin/'
        else:
            home_user = '/home/{}/'.format(me)
            user_bin = home_user + 'bin/'
            self._container.exec_run('mkdir -p ' + user_bin)
            self._container.exec_run('export PATH={}:$PATH'.format(user_bin))
            return user_bin

    def copy_to_container(self, src, dest):
        """Method to copy file from local file system into container"""
        # it's necessary create a tar file with src file/directory
        archive = None
        with NamedTemporaryFile(buffering=DEFAULT_BUFFER_SIZE, prefix="dockercp", delete=False) as fp:
            with tarfile.open(mode="w:bz2", fileobj=fp, bufsize=DEFAULT_BUFFER_SIZE) as tar:
                tar.add(src, arcname=path.basename(src))
            archive = fp.name
        # send the tar to the container
        if archive is not None:
            result = False
            with open(archive, "rb") as fp:
                result = self._container.put_archive(dest, fp)

                self._container.exec_run('bzip2 -dk {}/{}'.format(dest, archive))
            remove(archive)
            return result
        return False

    def copy_from_container(self, src, dest):
        """Method to copy file from container to local filesystem"""
        err, out = self._container.exec_run('base64 ' + src)
        if not err:
            with open(dest, 'wb') as fp:
                fp.write(b64decode(out))

        return err == 0

    def _check_qemu_install(self):
        """
        Check the install location of QEMU.
        """

        # if we have an image id, we create a container and copy qemu into it
        if self.os == "cgc":
            suffix = "tracer" if self._record_trace else "base"
            self.trace_source = "shellphish-qemu-cgc-%s" % suffix
        else:
            self.trace_source = "shellphish-qemu-linux-%s" % self._p.arch.qemu_name

        if self._trace_source_path is None or not os.access(self._trace_source_path, os.X_OK):
            if self._trace_source_path is not None:
                l.warning("Problem accessing forced %s. Using our default %s.") % (
                self._trace_source_path, self.trace_source)

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

        # first check whether qemu is alread
        qemu_bin = self._trace_source_path.split('/')[-1]
        self._docker_trace_source_path ='{}/{}'.format(self.docker_qemu_base_path, qemu_bin)
        err_code, _ = self._container.exec_run('ls ' + self._docker_trace_source_path)
        if err_code != 0:
            succ = self.copy_to_container(self._trace_source_path, self.docker_qemu_base_path)
            assert succ, "Unable to move QEMU executable in the contasiner"

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
        binaries_old = []
        for binary in self._binaries:
            binaries_old.append(binary)

        binary_replacements = []
        for i, binary in enumerate(self._binaries):
            binary_replacements.append(os.path.join(tmpdir, "binary_replacement_%d" % i))

        for binary_o, binary_r in zip(binaries_old, binary_replacements):
            shutil.copy(binary_o, binary_r)

        self._binaries = binary_replacements
        if self.argv is not None and not self.is_multicb:
            self.argv = self._binaries + self.argv[1:]
        os.chdir(tmpdir)
        try:
            yield (tmpdir, binary_replacements)
        finally:
            assert tmpdir.startswith(prefix)
            shutil.rmtree(tmpdir)
            os.chdir(curdir)
            resource.setrlimit(resource.RLIMIT_CORE, saved_limit)
            self._binaries = binaries_old

    def _run(self, stdout_file=None):
        with self._setup_env() as (tmpdir, binary_replacement_fname):
            self._container.exec_run('mkdir -p ' + tmpdir)
            [self.copy_to_container(fn, tmpdir) for fn in binary_replacement_fname]

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

    def _run_trace(self, stdout_file=None):
        if self.is_multicb:
            self._run_multicb_trace(stdout_file)
        else:
            self._run_singlecb_trace(stdout_file)

    def __get_rlimit_func(self):
        def set_fsize():
            # here we limit the logsize
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (self.trace_log_limit, self.trace_log_limit))

        return set_fsize

    def _run_multicb_trace(self, stdout_file=None):
        args = [self._fakeforksrv_path]
        args += self._binaries

        stderr_file = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-multicb-stderr-")

        saved_afl_path = os.environ.get('AFL_PATH', None)
        with open('/dev/null', 'wb') as devnull:
            os.environ['AFL_PATH'] = shellphish_afl.afl_dir('multi-cgc')

            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            stderr_f = open(stderr_file, 'wb')

            # TODO close_fds and set rlimit
            docker_args = ['timeout', str(self.trace_timeout),
                           'sh', '-c', 'echo -n "{}" | {}'.format(self.input.decode(), ' '.join(args))]
            self.returncode, out = self._container.exec_run(docker_args)
            if self.returncode == 0 and stdout_file is not None:
                stdout_f.write(str(out))
            else:
                if 'starting container process caused' in out:
                    out = out.split('starting container process caused ')[1:][0]
                stderr_f.write(out)

            if stdout_file is not None:
                stdout_f.close()

            stderr_f.close()

        if saved_afl_path:
            os.environ['AFL_PATH'] = saved_afl_path

        with open(stderr_file, 'rb') as f:
            buf = f.read()
            for line in buf.split(b"\n"):
                if b"signaled" in line:
                    self.crash_mode = bool(int(line.split(b":")[-1]))

    def _run_singlecb_trace(self, stdout_file=None):
        logname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        args = [self._docker_trace_source_path]

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

        # Memory limit option is only available in shellphish-qemu-cgc-*
        if 'cgc' in self._trace_source_path:
            args += ["-m", self._memory_limit]

        args += self.argv or [self._binaries[0]]

        if self._bitflip:
            args = [args[0]] + ["-bitflip"] + args[1:]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            # we assume qemu with always exit and won't block
            if type(self.input) is bytes:
                l.debug("Tracing as raw input")
                l.debug(" ".join(args))

                # TODO close_fds and set rlimit
                docker_args = ['timeout', str(self.trace_timeout),
                               'sh', '-c', 'echo -n "{}" | {}'.format(self.input.decode(), ' '.join(args))]
                self.returncode, out = self._container.exec_run(docker_args)
                if self.returncode == 0:
                    stdout_f.write(out)
            else:
                """
                in_s, out_s = socket.socketpair()
                p = subprocess.Popen(args, stdin=in_s, stdout=stdout_f,
                                     stderr=devnull,
                                     preexec_fn=self.__get_rlimit_func())

                for write in self.input.writes:
                    out_s.send(write)
                    time.sleep(.01)
                """

                l.debug("Tracing as pov file")
                raise NotImplementedError("Tracing as pov file: not yet implmeneted.")

            # did a crash occur?
            if self.returncode != 0:
                if abs(self.returncode) == signal.SIGSEGV or abs(self.returncode) == signal.SIGILL:
                    l.info("Input caused a crash (signal %d) during dynamic tracing", abs(self.returncode))
                    l.debug(repr(self.input))
                    l.debug("Crash mode is set")
                    self.crash_mode = True

            if stdout_file is not None:
                stdout_f.close()

        if self._record_trace:
            try:
                self.copy_from_container(logname, logname)
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
                    if m != None:
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
                l.warning("""One trace is found to be malformated,
                it is possible that the log file size exceeds the 1G limit,
                meaning that there might be infinite loops in the target program""")
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
        self.reg_vals = {reg: val for (reg, val) in p.loader.main_object.initial_register_values()}
        self._state = p.factory.entry_state()
        self.memory = self._state.memory

    def _load_tiny_core(self, core_file):
        tc = TinyCore(core_file)
        self.reg_vals = tc.registers
        self.memory = None
