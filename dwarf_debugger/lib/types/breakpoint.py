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

BREAKPOINT_NATIVE = 0
BREAKPOINT_JAVA = 1
BREAKPOINT_INITIALIZATION = 2
BREAKPOINT_OBJC = 3


class Breakpoint(object):
    def __init__(self, breakpoint_type):
        self.breakpoint_type = breakpoint_type
        self.target = None
        self.condition = ''
        self.debug_symbol = None

    def set_condition(self, condition):
        self.condition = condition

    def set_debug_symbol(self, symbol):
        self.debug_symbol = symbol

    def set_target(self, target):
        self.target = target

    def get_condition(self):
        return self.condition

    def get_target(self):
        return self.target

    def to_json(self):
        return {
            'target': self.target,
            'condition': self.condition,
            'debug_symbol': self.debug_symbol
        }
