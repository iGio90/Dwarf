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
from lib.register import Register
import unicorn


class Context(object):
    def __init__(self, context):
        if 'pc' in context:
            for register in context:
                if len(register) > 0 and register != 'toJSON':
                    self.__dict__[register] = Register(context[register])


class EmulatorContext(object):
    """
    holds emulator context related stuffs
    """

    def __init__(self, dwarf):
        import unicorn

        # map unicorn registers for the correct arch
        if dwarf.arch == 'arm':
            unicorn_consts = unicorn.arm_const
        elif dwarf.arch == 'arm64':
            unicorn_consts = unicorn.arm64_const
        elif dwarf.arch == 'ia32' or dwarf.arch == 'x64':
            unicorn_consts = unicorn.x86_const
        else:
            raise Exception('unsupported arch')

        self._unicorn_registers = {}

        for v in unicorn_consts.__dict__:
            if '_REG_' in v:
                reg = v.lower().split('_')[-1]
                if reg == 'invalid' or reg == 'ending':
                    continue
                self.__dict__[reg] = 0
                self._unicorn_registers[reg] = unicorn_consts.__dict__[v]

    def set_context(self, uc):
        for reg in self._unicorn_registers:
            try:
                self.__dict__[reg] = uc.reg_read(self._unicorn_registers[reg])
            except unicorn.unicorn.UcError:
                pass
