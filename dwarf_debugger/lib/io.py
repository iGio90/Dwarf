from PyQt5.QtCore import QThread, pyqtSignal
from dwarf_debugger.lib import utils


class Reader(QThread):
    ioReaderFinish = pyqtSignal(list, name='ioReaderFinish')

    def __init__(self, io, ptr, length):
        super().__init__()

        self.io = io
        self.dwarf = io.dwarf
        self.ptr = ptr
        self.length = length

    def run(self):
        ptr = self.ptr
        base = 0

        if self.length > 0:
            data = self.read_data()
        else:
            base, data = self.read_range_data()

        self.ioReaderFinish.emit([ptr, data, base])

    def read_range_data(self):
        data = bytes()
        base = 0
        try:
            _range = self.dwarf.dwarf_api('getRange', self.ptr)
            if _range:
                if _range['protection'][0] == 'r':
                    base = utils.parse_ptr(_range['base'])
                    self.ptr = base
                    self.length = _range['size']
                    hex_base = hex(base)
                    if hex_base in self.io.range_cache:
                        data = self.io.range_cache[hex_base]
                    else:
                        data = self.read_data()
                        if data:
                            self.io.range_cache[hex_base] = data
        except Exception as e:
            print('IO - failed to read data')
            raise e
        return base, data

    def read_data(self):
        if self.length > 1024 * 1024:
            position = 0
            next_size = 1024 * 1024
            data = bytearray()
            while True:
                try:
                    data += self.dwarf.dwarf_api('readBytes', [self.ptr + position, next_size])
                except:
                    return None
                position += next_size
                diff = self.length - position
                if diff > 1024 * 1024:
                    next_size = 1024 * 1024
                elif diff > 0:
                    next_size = diff
                else:
                    break
            ret = bytes(data)
            del data
            return ret
        else:
            r = self.dwarf.dwarf_api('readBytes', [self.ptr, self.length])
            if not r:
                r = bytes()
            return r


class IO:
    def __init__(self, dwarf):
        self.dwarf = dwarf
        self.refs = {}

        self.range_cache = {}

        self.dwarf.onThreadResumed.connect(self.clear_cache)

    def clear_cache(self):
        self.range_cache = {}

    def read(self, ptr, length):
        ptr = utils.parse_ptr(ptr)
        reader = Reader(self, ptr, length)
        return ptr, reader.read_data()

    def read_async(self, ptr, length, callback):
        ptr = utils.parse_ptr(ptr)
        reader = Reader(self, ptr, length)
        reader.ioReaderFinish.connect(lambda x: self._on_io_reader_finish(x[0], x[1], callback))
        self.refs[hex(ptr)] = reader
        reader.start()

    def read_range(self, ptr):
        ptr = utils.parse_ptr(ptr)
        reader = Reader(self, ptr, 0)
        base, data = reader.read_range_data()
        return base, data, ptr - base

    def read_range_async(self, ptr, callback):
        ptr = utils.parse_ptr(ptr)

        if hex(ptr) in self.refs:
            # already reading this range
            return

        reader = Reader(self, ptr, 0)
        reader.ioReaderFinish.connect(lambda x: self._on_io_reader_range_finish(x[0], x[1], x[2], callback))
        self.refs[hex(ptr)] = reader
        reader.start()

    def _on_io_reader_finish(self, ptr, data, callback):
        del self.refs[hex(ptr)]
        callback(ptr, data)

    def _on_io_reader_range_finish(self, ptr, data, base, callback):
        del self.refs[hex(ptr)]
        callback(base, data, ptr - base)
