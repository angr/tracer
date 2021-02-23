import logging
import struct

l = logging.getLogger(name=__name__)


class ParseError(Exception):
    pass


class CoreNote:
    """
    This class is used when parsing the NOTES section of a core file.
    """
    n_type_lookup = {
            1: 'NT_PRSTATUS',
            2: 'NT_PRFPREG',
            3: 'NT_PRPSINFO',
            4: 'NT_TASKSTRUCT',
            6: 'NT_AUXV',
            0x53494749: 'NT_SIGINFO',
            0x46494c45: 'NT_FILE',
            0x46e62b7f: 'NT_PRXFPREG'
            }

    def __init__(self, n_type, name, desc):
        self.n_type = n_type
        if n_type in CoreNote.n_type_lookup:
            self.n_type = CoreNote.n_type_lookup[n_type]
        self.name = name
        self.desc = desc

    def __repr__(self):
        return "<Note %s %s %#x>" % (self.name, self.n_type, len(self.desc))


class TinyCore:
    """
    A ELF core parser that just works.
    """

    ELF_FIELDS = {
        'e_ident[EI_CLASS]': {32: (4, 1), 64: (4, 1)},
        'e_ident[EI_DATA]': {32: (5, 1), 64: (5, 1)},
        'e_machine': {32: (0x12, 2), 64: (0x12, 2)},
        'e_phoff': {32: (0x1c, 4), 64: (0x20, 8)},
        'e_phnum': {32: (0x2c, 2), 64: (0x38, 2)},
        # offsets and sizes of fields in Program Header
        'p_offset': {32: (4, 4), 64: (8, 8)},
        'p_filesz': {32: (0x10, 4), 64: (0x20, 8)},
    }

    def __init__(self, filename):
        self.endian_format = "<"
        self.bits = None
        self.arch = None

        self.notes = []
        # siginfo
        self.si_signo = None
        self.si_code = None
        self.si_errno = None

        # prstatus
        self.pr_cursig = None
        self.pr_sigpend = None
        self.pr_sighold = None

        self.pr_pid = None
        self.pr_ppid = None
        self.pr_pgrp = None
        self.pr_sid = None

        self.pr_utime_usec = None
        self.pr_stime_usec = None
        self.pr_cutime_usec = None
        self.pr_cstime_usec = None

        self.registers = None

        self.pr_fpvalid = None
        self.filename = filename

        self.parse()

    def _set_arch(self, machine):
        if machine == 3:
            self.arch = "x86"
        elif machine == 8:
            self.arch = "mips"
        elif machine == 0x14:
            self.arch = "powerpc"
        elif machine == 0x28:
            self.arch = "arm"
        elif machine == 0x3e:
            self.arch = "x86-64"
        elif machine == 0xb7:
            self.arch = "aarch64"
        else:
            raise ValueError("Unsupported machine type %d." % machine)

    def _read_word(self, stream, size):
        return self._parse_word(stream.read(size))

    def _parse_word(self, data):
        size = len(data)
        if size == 1:
            format_specifier = "B"
        elif size == 2:
            format_specifier = "H"
        elif size == 4:
            format_specifier = "I"
        elif size == 8:
            format_specifier = "Q"
        else:
            raise TypeError('Unsupported word size %s.' % size)
        return struct.unpack(self.endian_format + format_specifier, data)[0]

    def parse(self):
        with open(self.filename, "rb") as f:
            # bits
            ei_class_off, ei_class_size = self.ELF_FIELDS['e_ident[EI_CLASS]'][32]
            f.seek(ei_class_off)
            ei_class_field = self._read_word(f, ei_class_size)
            if ei_class_field == 1:
                self.bits = 32
            elif ei_class_field == 2:
                self.bits = 64
            else:
                raise IOError("Cannot determine the bits of the core file. Are you sure the core file is correct?")

            ei_data_off, ei_data_size = self.ELF_FIELDS['e_ident[EI_DATA]'][32]
            f.seek(ei_data_off)
            ei_data_field = self._read_word(f, ei_data_size)
            if ei_data_field == 1:
                self.endian_format = "<"
            elif ei_data_field == 2:
                self.endian_format = ">"
            else:
                raise IOError("Cannot determine the endianness of the core file. Are you sure the core file is correct?")

            # architecture
            f.seek(self.ELF_FIELDS['e_machine'][self.bits][0])
            self._set_arch(self._read_word(f, self.ELF_FIELDS['e_machine'][self.bits][1]))

            # phoff
            f.seek(self.ELF_FIELDS['e_phoff'][self.bits][0])
            self.ph_off = self._read_word(f, self.ELF_FIELDS['e_phoff'][self.bits][1])
            # phnum
            f.seek(self.ELF_FIELDS['e_phnum'][self.bits][0])
            self.ph_num = self._read_word(f, self.ELF_FIELDS['e_phnum'][self.bits][1])

            f.seek(self.ph_off)

            ph_header_sizes = { 32: 0x20, 64: 0x38 }

            ph_headers = f.read(self.ph_num*ph_header_sizes[self.bits])

            for i in range(self.ph_num):
                off = i*ph_header_sizes[self.bits]
                p_type_packed = ph_headers[off:off+4]
                # be careful
                if len(p_type_packed) != 4:
                    continue
                p_type = struct.unpack(self.endian_format + "I", p_type_packed)[0]
                if p_type == 4:  # note
                    p_offset_off, p_offset_size = self.ELF_FIELDS['p_offset'][self.bits]
                    p_filesz_off, p_filesz_size = self.ELF_FIELDS['p_filesz'][self.bits]
                    note_offset_packed = ph_headers[off + p_offset_off : off + p_offset_off + p_offset_size]
                    note_size_packed = ph_headers[off + p_filesz_off : off + p_filesz_off + p_filesz_size]
                    # be careful
                    if len(note_offset_packed) != p_offset_size or len(note_size_packed) != p_filesz_size:
                        continue
                    note_offset = self._parse_word(note_offset_packed)
                    note_size = self._parse_word(note_size_packed)
                    if note_size > 0x100000:
                        l.warning("note size > 0x100000")
                        note_size = 0x100000
                    f.seek(note_offset)
                    note_data = f.read(note_size)
                    parsed = self._parse_notes(note_data)
                    if parsed:
                        return
        raise ParseError("failed to find registers in core")

    def _parse_notes(self, note_data):
        """
        This exists, because note parsing in elftools is not good.
        """

        blob = note_data

        note_pos = 0
        while note_pos < len(blob):
            to_unpack = blob[note_pos:note_pos+12]
            if len(to_unpack) != 12:
                break
            name_sz, desc_sz, n_type = struct.unpack(self.endian_format + "3I", to_unpack)
            name_sz_rounded = (((name_sz + (4 - 1)) // 4) * 4)
            desc_sz_rounded = (((desc_sz + (4 - 1)) // 4) * 4)
            # description size + the rounded name size + header size
            n_size = desc_sz_rounded + name_sz_rounded + 12

            # name_sz includes the null byte
            name = blob[note_pos+12:note_pos+12+name_sz-1]
            desc = blob[note_pos+12+name_sz_rounded:note_pos+12+name_sz_rounded+desc_sz]

            self.notes.append(CoreNote(n_type, name, desc))
            note_pos += n_size

        # prstatus
        prstatus_list = [x for x in self.notes if x.n_type == 'NT_PRSTATUS']
        if len(prstatus_list) > 1:
            l.warning("multiple prstatus")
        if len(prstatus_list) == 0:
            raise ParseError("no prstatus")
        for prstatus in prstatus_list:
            try:
                self._parse_prstatus(prstatus)
                return True
            except struct.error as e:
                l.warning(e)
        return False

    def _parse_prstatus(self, prstatus):
        """
        Parse out the prstatus, accumulating the general purpose register values. Supports X86 and MIPS32 at the moment.

        :param prstatus: a note object of type NT_PRSTATUS.
        """

        # extract siginfo from prstatus
        self.si_signo, self.si_code, self.si_errno = struct.unpack(self.endian_format+"3I", prstatus.desc[:12])

        # this field is a short, but it's padded to an int
        self.pr_cursig = struct.unpack(self.endian_format+"I", prstatus.desc[12:16])[0]

        arch_bytes = self.bits // 8
        # TODO: Does endianness matter?
        if arch_bytes == 4:
            fmt = "I"
        elif arch_bytes == 8:
            fmt = "Q"
        else:
            raise ParseError("Architecture must have a bitwidth of either 64 or 32")

        self.pr_sigpend, self.pr_sighold = struct.unpack(self.endian_format + (fmt * 2), prstatus.desc[16:16 + (2 * arch_bytes)])

        attrs = struct.unpack(self.endian_format + "IIII", prstatus.desc[16 + (2 * arch_bytes):16 + (2 * arch_bytes) + (4 * 4)])
        self.pr_pid, self.pr_ppid, self.pr_pgrp, self.pr_sid = attrs

        # parse out the 4 timevals
        pos = 16 + (2 * arch_bytes) + (4 * 4)
        usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_utime_usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_stime_usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_cutime_usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_cstime_usec = struct.unpack(self.endian_format + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2

        # parse out general purpose registers
        if self.arch == "x86":
            rnames = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs', 'gs', 'xxx', 'eip',
                      'cs', 'eflags', 'esp', 'ss']
        elif self.arch == "x86-64":
            rnames = ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10',
                      'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax',
                      'rip', 'cs', 'eflags', 'rsp', 'ss',
                      'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs',
                      ]
        elif self.arch == "mips":
            pos += arch_bytes * 6  # 6 words of padding
            rnames = ['zero', 'at', 'v0', 'v1',
                      'a0', 'a1', 'a2', 'a3',
                      't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                      's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                      't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra',
                      'lo', 'hi', 'pc',
                      ]
        elif self.arch == "arm":
            rnames = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9',
                      'r10', 'fp', 'r12', 'sp', 'lr', 'pc', 'cpsr'] # r10 is also known as sl, r12 as ip
        else:
            raise ValueError("Architecture %s is currently unsupported." % self.arch)

        nreg = len(rnames)

        regvals = []
        for idx in range(pos, pos + nreg * arch_bytes, arch_bytes):
            regvals.append(struct.unpack(self.endian_format + fmt, prstatus.desc[idx:idx + arch_bytes])[0])
        self.registers = dict(zip(rnames, regvals))

        self.registers.pop('xxx', None)

        pos += nreg * arch_bytes
        self.pr_fpvalid = struct.unpack(self.endian_format + "I", prstatus.desc[pos:pos + 4])[0]
        return True

