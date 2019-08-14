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
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""


import json

from capstone import *
from capstone.arm64_const import *
from PyQt5.QtCore import QThread, pyqtSignal

from dwarf.lib.types.instruction import Instruction


class DisassembleThread(QThread):
    """ Disasm Thread
    """
    onFinished = pyqtSignal(list, name='onFinished')
    onError = pyqtSignal(str, name='onError')

    def __init__(self, dwarf, capstone, base, data, offset, num_instructions=-1, max_instructions=1024, stop_on_first_return=False):
        super().__init__()
        self._dwarf = dwarf
        self._base = base
        self._data = data
        self._offset = offset
        self._capstone = capstone
        # TODO: remove - only there to keep working - change in disasm() calls
        if num_instructions == 0:
            num_instructions = -1
            stop_on_first_return = True
        # end remove
        self._num_instructions = num_instructions
        self._max_instructions = max_instructions
        self._stop_on_ret = stop_on_first_return

    def run(self):
        """ dont call this - use start
        """
        if not self._data:
            self.onError.emit('No Data')
            return

        if not self._capstone:
            self.onError.emit('No Capstone')
            return

        if not self._dwarf:
            self.onError.emit('No Dwarf')
            return

        if not self._num_instructions or not self._max_instructions:
            self.onError.emit('Nothing todo...')
            return

        instructions_count = 0

        instructions = []
        debug_symbols = []
        debug_symbols_indexes = []

        for cap_inst in self._capstone.disasm(
                self._data[self._offset:], self._base + self._offset):

            dwarf_instruction = Instruction(self._dwarf, cap_inst)
            if dwarf_instruction.is_jump and dwarf_instruction.jump_address:
                debug_symbols.append(dwarf_instruction.jump_address)
                debug_symbols_indexes.append(str(len(instructions)))
            elif dwarf_instruction.is_call and dwarf_instruction.call_address:
                debug_symbols.append(dwarf_instruction.call_address)
                debug_symbols_indexes.append(str(len(instructions)))

            instructions.append(dwarf_instruction)

            instructions_count += 1

            # num_instructions set and reached?
            if self._num_instructions > 0 and instructions_count >= self._num_instructions:
                break

            # stop on first return?
            if self._stop_on_ret:
                # is return -> stop TODO: unsafe when using -1 on num_instr and max_instr
                if cap_inst.group(CS_GRP_RET) or cap_inst.group(ARM64_GRP_RET):
                    break

            # TODO: add stop_on_function_end via function epilogue

            # max instructions set and reached?
            if self._max_instructions > 0 and self._num_instructions == -1:
                if instructions_count >= self._max_instructions:
                    break

        if debug_symbols:
            symbols = self._dwarf.dwarf_api('getDebugSymbols', json.dumps(debug_symbols))
            if symbols:
                for index, symbol in enumerate(symbols):
                    inst_index = None
                    try:
                        inst_index = int(debug_symbols_indexes[index])
                    except ValueError:
                        pass

                    if inst_index is not None:
                        instruction = instructions[inst_index]
                        instruction.symbol_name = ''
                        instruction.symbol_module = '-'
                        if 'name' in symbol:
                            instruction.symbol_name = symbol['name']
                        if 'moduleName' in symbol:
                            instruction.symbol_module = symbol['moduleName']

        self.onFinished.emit(instructions)


class Disassembler:
    def __init__(self, dwarf):
        self.dwarf = dwarf

        self.dwarf.onApplyContext.connect(self.on_arch_changed)

        self._capstone = None
        self._disasm_thread = None

        self.capstone_arch = 0
        self.capstone_mode = 0
        self.keystone_arch = 0
        self.keystone_mode = 0

        self.on_arch_changed()

    def disasm(self, base, data, offset, callback, num_instructions=-1):
        self._disasm_thread = DisassembleThread(
            self.dwarf, self._capstone, base, data, offset, num_instructions=num_instructions)
        self._disasm_thread.onFinished.connect(callback)
        # TODO: handle onError
        self._disasm_thread.start(QThread.HighestPriority)

    def on_arch_changed(self):
        if self.dwarf.arch == 'arm64':
            self.capstone_arch = CS_ARCH_ARM64
            self.capstone_mode = CS_MODE_LITTLE_ENDIAN
        elif self.dwarf.arch == 'arm':
            self.capstone_arch = CS_ARCH_ARM
            context = self.dwarf.current_context()
            self.capstone_mode = CS_MODE_ARM
            if context is not None and context.is_native_context:
                if context.pc.thumb:
                    self.capstone_mode = CS_MODE_THUMB
        elif self.dwarf.arch == 'ia32':
            self.capstone_arch = CS_ARCH_X86
            self.capstone_mode = CS_MODE_32
        elif self.dwarf.arch == 'x64':
            self.capstone_arch = CS_ARCH_X86
            self.capstone_mode = CS_MODE_64
        if self.dwarf.keystone_installed:
            import keystone.keystone_const as ks
            if self.dwarf.arch == 'arm64':
                self.keystone_arch = ks.KS_ARCH_ARM64
                self.keystone_mode = ks.KS_MODE_LITTLE_ENDIAN
            elif self.dwarf.arch == 'arm':
                self.keystone_arch = ks.KS_ARCH_ARM
                self.keystone_mode = ks.KS_MODE_ARM
            elif self.dwarf.arch == 'ia32':
                self.keystone_arch = ks.KS_ARCH_X86
                self.keystone_mode = ks.KS_MODE_32
            elif self.dwarf.arch == 'x64':
                self.keystone_arch = ks.KS_ARCH_X86
                self.keystone_mode = ks.KS_MODE_64

        self._capstone = Cs(self.capstone_arch, self.capstone_mode)
        self._capstone.detail = True
        # self._capstone.skipdata = True
