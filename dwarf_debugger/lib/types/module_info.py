"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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
from dwarf_debugger.lib.types.function import Function


class ModuleInfo:

    def __init__(self, module_base_info):
        self._updated_details = False

        if not module_base_info:
            return None

        if not 'name' in module_base_info:
            return None

        self.name = module_base_info['name']
        self.base = int(module_base_info['base'], 16)
        self.size = module_base_info['size']
        self.path = module_base_info['path']

        self.sections = {}

        self.functions = []
        self.functions_map = {}

        # frida objects
        self.exports = []
        self.imports = []
        self.symbols = []

        if 'symbols' in module_base_info and isinstance(module_base_info['symbols'], list):
            self.apply_symbols(module_base_info['symbols'])
        if 'imports' in module_base_info and isinstance(module_base_info['imports'], list):
            self.apply_imports(module_base_info['imports'])
        if 'exports' in module_base_info and isinstance(module_base_info['exports'], list):
            self.apply_exports(module_base_info['exports'])


    @property
    def have_details(self):
        return self._updated_details

    @staticmethod
    def build_module_info_with_data(data):
        module_info = ModuleInfo(data)
        return module_info

    @staticmethod
    def build_module_info(dwarf, name_or_address, fill_ied=False):
        module_base_info = dwarf.dwarf_api('findModule', [name_or_address, fill_ied])

        if module_base_info:
            db_module_info = dwarf.database.get_module_info(module_base_info['base'])
            if db_module_info:
                if not db_module_info.have_details and fill_ied:
                    db_module_info.update_details(dwarf, module_base_info)
                return db_module_info

            if module_base_info:
                module_info = ModuleInfo(module_base_info)

                if fill_ied:
                    module_info.update_details(dwarf, module_base_info)

                dwarf.database.put_module_info(module_base_info['base'], module_info)

                return module_info
        return None

    def apply_symbols(self, module_symbols):
        self.symbols = module_symbols
        for symbol in module_symbols:
            if 'section' in symbol:
                section = symbol['section']
                section_id = section['id']

                if section_id not in self.sections:
                    self.sections[section_id] = section

            self.parse_symbol(symbol)

    def apply_imports(self, imports):
        self.imports = imports

    def apply_exports(self, exports):
        self.exports = exports
        for export in exports:
            self.parse_symbol(export, exported=True)

    def parse_symbol(self, symbol, exported=False):
        type_ = symbol['type']
        if type_ == 'function':
            # needs to check if address is in symbol. i saw this
            # {'name': '_ZN15QXcbIntegrationC1ERK11QStringListRiPPc', 'type': 'function'}
            if 'address' in symbol and symbol['address'] not in self.functions_map:
                f = Function(symbol, exported=exported)
                self.functions.append(f)
                self.functions_map[symbol['address']] = f

    def update_details(self, dwarf, base_info):
        details = dwarf.dwarf_api('enumerateModuleInfo', base_info['name'])

        self._updated_details = True

        if 'symbols' in details and isinstance(details['symbols'], list):
            self.apply_symbols(details['symbols'])
        if 'imports' in details and isinstance(details['imports'], list):
            self.apply_imports(details['imports'])
        if 'exports' in details and isinstance(details['exports'], list):
            self.apply_exports(details['exports'])
