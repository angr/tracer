import xml.etree.ElementTree

from angr.storage.file import SimPacketsSlots

class TracerPoV(object):
    """
    Simple PoV parser for Tracer.
    """

    def __init__(self, filename):
        self.filename = filename

        self._root = xml.etree.ElementTree.parse(self.filename)

        self._raw_writes = self._root.find('replay').findall('write')

        self._raw_reads = self._root.find('replay').findall('read')
        self._variable_declarations = self._root.find('replay').findall('decl')
        self._collect_variables()
        self._clean_writes()
        self.stdin = self._prepare_dialogue()

    def _collect_variables(self):
        self._variables = dict()
        for variable_declaration in self._variable_declarations:
            variable_name = None
            variable_value = ""
            for ele in variable_declaration:
                if ele.tag == 'var':
                    variable_name = ele.text
                elif ele.tag == 'value':
                    variable_data = list(ele)[0]
                    assert(variable_data.tag == 'data')
                    variable_value = variable_data.text

            if variable_name:
                self._variables[variable_name] = variable_value

        for raw_read in self._raw_reads:
            current_var = ""
            for ele in raw_read:
                if ele.tag == 'delim':
                    current_var = ele.text
                elif ele.tag == 'data':
                    current_var = ele.text
                elif ele.tag == 'assign':
                    varname = ele.find('var').text
                    if not ele.find('slice') is None:
                        begin = ele.find('slice').attrib.get('begin')
                        end = ele.find('slice').attrib.get('end')
                        if not begin is None: begin = int(begin)
                        if not end is None:
                            end = int(end)
                            if end == -1:
                                end = None
                            elif end < -1:
                                end = end - 1
                    else:
                        begin = None
                        end = None
                    self._variables[varname] = current_var[begin:end]

    def _clean_writes(self):
        """
        Decode writes.
        """

        self.writes = []
        for raw_write in self._raw_writes:
            mode = 'ascii'
            if 'format' in raw_write.attrib:
                mode = raw_write.attrib['format']
            d = filter(lambda ele:
                    ele.tag == 'data' or ele.tag == 'var',
                    raw_write)
            if d is None:
                raise ValueError("could not find data tag inside write element, unsupport element")

            body = b''
            for i in d:
                mode_i = i.attrib.get('format', mode)
                if i.tag == 'data':
                    text = i.text
                else:
                    text = self._variables[i.text]
                if mode_i == 'ascii' or mode_i == 'asciic':
                    body += text.encode('utf-8').decode('unicode_escape').encode('latin-1')
                elif mode_i == 'hex':
                    body += bytes.fromhex(text.strip().replace('\n', ''))
                else:
                    raise ValueError("unrecognized mode '%s' in file '%s'" % (mode_i, self.filename))
            self.writes.append(body)

    def _prepare_dialogue(self):
        """
        Prepare a data storage entry for stdin
        """
        s = SimPacketsSlots('stdin', [len(write) for write in self.writes])
        return {"/dev/stdin": s}

def test():
    tracerpov = TracerPoV('../tests/for-release__GEN_00391.xml')
    print(tracerpov.writes)

if __name__ == "__main__":
    test()
