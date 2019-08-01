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
from dwarf.lib import utils


class Database:
    """ DwarfDatabase
    """

    def __init__(self, dwarf):
        super().__init__()
        self.modules_info = {}
        self.ranges_info = {}

        dwarf.onThreadResumed.connect(self._clean_ranges_cache)

    def _clean_ranges_cache(self):
        # files will be cleaned on next db creation. to cleanup cache is enough to remove info from the map
        # we clean only ranges with writable permissions
        for _range_address in list(self.ranges_info.keys()):
            perm = self.ranges_info[_range_address].permissions
            if 'w' in perm:
                del self.ranges_info[_range_address]

    def get_module_info(self, address):
        address = self.sanify_address(address)
        if address:
            try:
                address = int(address, 16)
            except ValueError:
                return None

            for module_info in self.modules_info:
                _module = self.modules_info[module_info]
                if _module:
                    if _module.base <= address <= _module.base + _module.size:
                        return _module

        return None

    def get_range_info(self, address):
        address = utils.parse_ptr(address)

        for hex_base in self.ranges_info:
            dwarf_range = self.ranges_info[hex_base]
            if address > dwarf_range.base:
                if address < dwarf_range.tail:
                    return dwarf_range
                return None
        return None

    def put_module_info(self, address, module_info):
        address = self.sanify_address(address)
        self.modules_info[address] = module_info
        return module_info

    def put_range_info(self, dwarf_range):
        base = hex(dwarf_range.base)
        self.ranges_info[base] = dwarf_range

    @staticmethod
    def sanify_address(address):
        hex_adr = address
        if isinstance(hex_adr, int):
            hex_adr = hex(hex_adr)
        return hex_adr.lower()
