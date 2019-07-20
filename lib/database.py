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
import os
import shutil

class Database:
    """ DwarfDatabase
    """
    def __init__(self, dwarf):
        self.modules_info = {}
        self.ranges_info = {}

        self._ranges_path = '.ranges'
        if os.path.exists(self._ranges_path):
            shutil.rmtree(self._ranges_path)
        os.mkdir(self._ranges_path)

        dwarf.onThreadResumed.connect(self._clean_ranges_cache)

    def _clean_ranges_cache(self):
        # files will be cleaned on next db creation. to cleanup cache is enough to remove info from the map
        # we clean only ranges with writable permissions
        for _range in list(self.ranges_info.keys()):
            perm = self.ranges_info[_range]
            if 'w' in perm:
                del self.ranges_info[_range]

    def get_module_info(self, address):
        address = self.sanify_address(address)
        if address:
            try:
                address = int(address, 16)
            except ValueError:
                return None

            for module_info in self.modules_info:
                _module = self.modules_info[module_info]
                if _module.base <= address <= _module.base + _module.size:
                    return _module

        return None

    def get_range_data(self, address):
        address = self.sanify_address(address)
        if address in self.ranges_info:
            cache_path = os.path.join(self._ranges_path, address)
            if os.path.exists(cache_path):
                with open(cache_path, 'rb') as f:
                    return f.read()
        return None

    def put_module_info(self, address, module_info):
        address = self.sanify_address(address)
        self.modules_info[address] = module_info
        return module_info

    def put_range_data(self, address, permissions, data):
        address = self.sanify_address(address)
        if data is not None:
            self.ranges_info[address] = permissions
            with open(os.path.join(self._ranges_path, address), 'wb') as f:
                f.write(data)

    def sanify_address(self, address):
        hex_adr = address
        if isinstance(hex_adr, int):
            hex_adr = hex(hex_adr)
        return hex_adr.lower()
