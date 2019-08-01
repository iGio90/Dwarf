"""
Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""
from PyQt5.QtCore import pyqtSignal, QThread

from dwarf.lib import utils
from dwarf.lib.types.module_info import ModuleInfo


class AsyncInitialization(QThread):
    onRangeAsyncInitializationFinish = pyqtSignal(list, name='onRangeAsyncInitializationFinish')

    def __init__(self, dwarf_range, dwarf, address, cb):
        super().__init__()
        self.dwarf_range = dwarf_range
        self.dwarf = dwarf
        self.address = address
        self.cb = cb

    def run(self):
        self.dwarf_range.init_with_address(self.dwarf, self.address)
        self.onRangeAsyncInitializationFinish.emit([self.dwarf, self.cb])


class Range:
    def __init__(self):
        self.base = 0
        self.size = 0
        self.tail = 0
        self.data = bytes()
        self.permissions = '---'

        self.module_info = None
        self.read_memory_thread = None

        self.user_req_start_address = 0
        self.user_req_start_offset = 0

    @staticmethod
    def build_or_get(dwarf, address, cb=None):
        address = utils.parse_ptr(address)
        hex_address = hex(address)
        dwarf_range = dwarf.database.get_range_info(hex_address)
        if dwarf_range is not None:
            dwarf_range.user_req_start_address = address
            dwarf_range.user_req_start_offset = address - dwarf_range.base
            if cb is not None:
                cb(dwarf_range)
            return dwarf_range

        dwarf_range = Range()
        dwarf.database.put_range_info(dwarf_range)

        if cb is not None:
            dwarf._app_window.show_progress('reading at %s' % hex_address)
            dwarf_range.init_with_address_async(dwarf, address, cb)
        else:
            dwarf_range.init_with_address(dwarf, address)
        return dwarf_range

    def init_with_address_async(self, dwarf, address, cb=None):
        self.read_memory_thread = AsyncInitialization(self, dwarf, address, cb)
        self.read_memory_thread.onRangeAsyncInitializationFinish.connect(self.on_finish_memory_read)
        self.read_memory_thread.start()

    def init_with_address(self, dwarf, address):
        self.user_req_start_address = address
        self.read_data(dwarf)

        if self.data is None:
            self.data = bytes()

    def on_finish_memory_read(self, data):
        dwarf = data[0]
        cb = data[1]

        dwarf._app_window.hide_progress()

        if cb is not None:
            cb(self)

    def read_data(self, dwarf):
        try:
            _range = dwarf.dwarf_api('getRange', self.user_req_start_address)
        except Exception:
            return 1
        if _range is None or len(_range) == 0:
            return 1

        # setup range fields
        self.base = int(_range['base'], 16)

        self.size = _range['size']
        self.tail = self.base + self.size
        self.user_req_start_offset = self.user_req_start_address - self.base
        self.permissions = _range['protection']

        self.data = dwarf.read_memory(self.base, self.size)

        # get module info for this range
        self.module_info = dwarf.database.get_module_info(_range['base'])
        if self.module_info is None:
            self.module_info = ModuleInfo.build_module_info(dwarf, self.base, fill_ied=True)
        elif not self.module_info.have_details:
            self.module_info.update_details(dwarf)

    def patch_bytes(self, _bytes, offset):
        data_bt = bytearray(self.data)
        org_bytes = bytes.fromhex(_bytes)
        data_bt[offset:offset+len(org_bytes)] = org_bytes
        self.data = bytes(data_bt)

    def set_start_offset(self, offset):
        self.user_req_start_offset = offset
        self.user_req_start_address = self.base + offset
