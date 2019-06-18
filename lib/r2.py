import r2pipe
from PyQt5.QtCore import QObject, QThread

from lib.rap.remote import RapServer


class DwarfRapServer(QThread):
    def __init__(self, dwarf):
        super(DwarfRapServer, self).__init__()

        self.dwarf = dwarf

        self.rs = None
        self.current_seek = 0
        self.rs = RapServer()
        self.rs.handle_read = self._read
        self.rs.handle_seek = self._seek
        #self.rs.handle_write = self._write
        self.rs.size = 10

    def run(self):
        self.rs.listen_tcp(9999)

    def _read(self, len_):
        ret = self.dwarf.dwarf_api('readBytes', [self.current_seek, len_])
        if ret is None:
            return b'\0' * len_
        return len_

    def _seek(self, off, type):
        self.current_seek = off
        return off

    def _write(self, buf):
        #self.dwarf.dwarf_api('writeBytes', [self.current_seek, buf])
        return 6


class R2Dwarf(QObject):
    def __init__(self, dwarf, parent=None):
        super(R2Dwarf, self).__init__(parent=parent)
        self.dwarf = dwarf

        self.available = False

        self.rap_server = DwarfRapServer(dwarf).start()
        self.r2 = r2pipe.open("rap://localhost:9999")

        version = self.r2.cmd('?V')
        self.available = version is not None and len(version) > 2

    def api(self, cmd):
        if not self.available:
            return None
        return self.r2.cmd(cmd).decode('utf8')
