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


class Kernel(object):
    def __init__(self, dwarf):
        self.dwarf = dwarf

    def is_available(self):
        return self.dwarf.dwarf_api('evaluate', ['kernel.available()', True]).startswith('a')

    def lookup_symbol(self, symbol):
        return self.dwarf.dwarf_api('evaluate', ['kernel.lookupSymbol(\'%s\')' % symbol])
