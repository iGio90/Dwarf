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


class Hook(object):
    HOOK_NATIVE = 0
    HOOK_JAVA = 1
    HOOK_ONLOAD = 2

    def __init__(self, hook_type):
        self.hook_type = hook_type
        self.ptr = 0
        self.input = ''
        self.condition = ''
        self.logic = ''

        # hold the original bytes of address + (pointer size * 2)
        # to be used from Range class when dumping memory and avoid showing frida asm trampolines
        self._bytes = bytes()

    def set_bytes(self, _bytes):
        self._bytes = _bytes

    def set_condition(self, condition):
        self.condition = condition

    def set_input(self, input):
        self.input = input

    def set_logic(self, logic):
        self.logic = logic

    def set_ptr(self, ptr):
        self.ptr = ptr

    def get_bytes(self):
        return self._bytes

    def get_condition(self):
        return self.condition

    def get_input(self):
        return self.input

    def get_logic(self):
        return self.logic

    def get_ptr(self):
        if self.ptr == 1:
            # for java hooks, return class and method
            return self.input
        return self.ptr
