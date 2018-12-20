"""
Dwarf - Copyright (C) 2018 iGio90

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


class Variable(object):
    def __init__(self, key, value, type, input):
        self.key = key
        self.value = value
        self.type = type
        self.input = input

    def get_key(self):
        return self.key

    def get_input(self):
        return self.input

    def get_type(self):
        return self.type

    def get_value(self):
        return self.value
