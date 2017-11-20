import angr
from angr.exploration_techniques import CrashMonitor, Oppologist

from . import QEMURunner
from . import TracerPoV

import logging

class Tracer(object):
    """
    Compatibility layer for Tracer exploration technique.
    """

    def __init__(self, binary, input=None, pov_file=None, simprocedures=None, #pylint:disable=redefined-builtin
                 hooks=None, seed=None, preconstrain_input=True,
                 preconstrain_flag=True, resiliency=True, chroot=None,
                 add_options=None, remove_options=None, trim_history=True,
                 project=None, dump_syscall=False, dump_cache=True,
                 max_size = None, exclude_sim_procedures_list=None,
                 argv=None, keep_predecessors=1):
        """
        :param binary                     : Path to the binary to be traced.
        :param input                      : Concrete input string to feed to binary.
        :param pov_file                   : CGC PoV describing the input to trace.
        :param hooks                      : Dictionary of hooks to add.
        :param simprocedures              : Dictionary of replacement simprocedures.
        :param seed                       : Optional seed used for randomness, will be passed to QEMU.
        :param preconstrain_input         : Should the path be preconstrained to the provided input.
        :param preconstrain_flag          : Should the path have the cgc flag page preconstrained.
        :param resiliency                 : Should we continue to step forward even if qemu and angr disagree?
        :param chroot                     : Trace the program as though it were executing in a chroot.
        :param add_options                : Add options to the state which used to do tracing.
        :param remove_options             : Remove options from the state which is used to do tracing.
        :param trim_history               : Trim the history of a path.
        :param project                    : The original project.
        :param dump_syscall               : True if we want to dump the syscall information.
        :param max_size                   : Optionally set max size of input. Defaults to size of preconstrained input.
        :param exclude_sim_procedures_list: What SimProcedures to hook or not at load time. Defaults to
                                            ["malloc","free","calloc","realloc"].
        :param argv                       : Optionally specify argv params (i,e,: ['./calc', 'parm1']). Defaults
                                            to binary name with no params.
        :param keep_predecessors          : Number of states before the final state we should preserve. Default 1,
                                            must be greater than 0.
        """

        msg = "Tracer package is deprecated, please use Tracer and CrashMonitor exploration techniques instead."
        logging.getLogger("tracer.tracer").warning(msg)

        if pov_file is not None and input is not None:
            raise ValueError("Cannot specify both a pov_file and an input.")

        if pov_file is not None:
            input = TracerPoV(pov_file)

        exclude_sim_procedures_list = exclude_sim_procedures_list or ('malloc', 'free', 'calloc', 'realloc')
        simprocedures = {} if simprocedures is None else simprocedures
        hooks = {} if hooks is None else hooks

        self.r = QEMURunner(binary=binary, input=input, seed=seed, argv=argv, project=project)
        p = angr.Project(binary, exclude_sim_procedures_list=exclude_sim_procedures_list)

        for addr, proc in hooks.iteritems():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)

        if p.loader.main_object.os == 'cgc':
            p._simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

            for symbol in simprocedures:
                angrSIM_LIBRARIES['cgcabi'].add(symbol, simprocedures[symbol])

            s = p.factory.tracer_state(input_content=input,
                                       magic_content=self.r.magic,
                                       preconstrain_input=preconstrain_input,
                                       preconstrain_flag=preconstrain_flag,
                                       add_options=add_options if add_options is not None else set(),
                                       remove_options=remove_options if remove_options is not None else set())
        elif p.loader.main_object.os.startswith('UNIX'):
            for symbol in simprocedures:
                p.hook_symbol(symbol, simprocedures[symbol])

            s = p.factory.tracer_state(input_content=input,
                                       magic_content=self.r.magic,
                                       preconstrain_input=preconstrain_input,
                                       preconstrain_flag=preconstrain_flag,
                                       add_options=add_options if add_options is not None else set(),
                                       remove_options=remove_options if remove_options is not None else set(),
                                       chroot=chroot,
                                       args=argv)

        self.simgr = p.factory.simgr(s,
                                     save_unsat=True,
                                     hierarchy=False,
                                     save_unconstrained=self.r.crash_mode)
        self.t = angr.exploration_techniques.Tracer(trace=self.r.trace,
                                                    resiliency=resiliency,
                                                    dump_syscall=dump_syscall,
                                                    keep_predecessors=keep_predecessors)
        self.c = CrashMonitor(trace=self.r.trace,
                              trim_history=trim_history,
                              crash_mode=self.r.crash_mode,
                              crash_addr=self.r.crash_addr)

        self.simgr.use_technique(self.c)
        self.simgr.use_technique(self.t)
        self.simgr.use_technique(angr.exploration_techniques.Oppologist())

    def run(self):
        self.simgr.run()
        if self.r.crash_mode:
            return self.t.predecessors[-1], self.simgr.crashed[0]
        else:
            return self.simgr.traced[0], None

    def dynamic_trace(self):
        return self.r.trace
