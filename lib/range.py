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

from lib import utils
from lib.types.module_info import ModuleInfo


class Range(object):
    # dump memory from target proc
    SOURCE_TARGET = 0
    # dump memory from emulator proc
    SOURCE_EMULATOR = 1

    def __init__(self, source, dwarf):
        super().__init__()

        self.source = source
        self.dwarf = dwarf

        self.base = 0
        self.size = 0
        self.tail = 0
        self.data = bytes()
        self.permissions = '---'

        self.start_address = 0
        self.start_offset = 0

        self.module_info = None

    def invalidate(self):
        self.base = 0
        self.size = 0
        self.tail = 0
        self.data = bytes()

        self.start_address = 0
        self.start_offset = 0

    def init_with_address(self, address, length=0, base=0, require_data=True):
        self.start_address = utils.parse_ptr(address)

        if self.base > 0:
            if self.base < self.start_address < self.tail:
                self.start_offset = self.start_address - self.base
                return -1

        if self.source == Range.SOURCE_TARGET:
            try:
                _range = self.dwarf.dwarf_api('getRange', self.start_address)
            except Exception as e:
                print(e)
                return 1
            if _range is None or len(_range) == 0:
                return 1

            # setup range fields
            self.base = int(_range['base'], 16)
            if base > 0:
                self.base = base
            self.size = _range['size']
            if 0 < length < self.size:
                self.size = length
            self.tail = self.base + self.size
            self.start_offset = self.start_address - self.base
            self.permissions = _range['protection']

            if require_data:
                # read data
                self.data = self.dwarf.read_memory(self.base, self.size)

            # get module info for this range
            # TODO: check why!!! when not listed in process.modules
            """self.module_info = self.dwarf.database.get_module_info(_range['base'])
            if self.module_info is None:
                self.module_info = ModuleInfo.build_module_info(self.dwarf, self.base, fill_ied=True)
                self.dwarf.database.put_module_info(_range['base'], self.module_info)
            elif self.module_info.have_details:
                self.module_info.update_details(self.dwarf)"""

        elif self.source == Range.SOURCE_EMULATOR:
            uc = self.dwarf.get_emulator().uc
            if uc is not None:
                for base, tail, perm in uc.mem_regions():
                    if base <= self.start_address <= tail:
                        self.base = base
                        self.tail = tail
                        self.start_offset = self.start_address - self.base
                        self.size = self.tail - self.base
                        break
                if self.base > 0 and require_data:
                    # read data
                    self.data = uc.mem_read(self.base, self.size)
        if self.data is None:
            self.data = bytes()
            return 1
        if len(self.data) == 0:
            return 1
        return 0

    def patch_bytes(self, _bytes, offset):
        data_bt = bytearray(self.data)
        org_bytes = bytes.fromhex(_bytes)
        data_bt[offset:offset+len(org_bytes)] = org_bytes
        self.data = bytes(data_bt)

    def set_start_offset(self, offset):
        self.start_offset = offset
        self.start_address = self.base + offset
