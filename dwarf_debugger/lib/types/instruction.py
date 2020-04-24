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
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM, CS_OP_REG, CS_OP_MEM
from capstone.arm_const import ARM_GRP_THUMB, ARM_GRP_THUMB2, ARM_GRP_THUMB1ONLY, ARM_GRP_THUMB2DSP

EXCHANGE_INSTRUCTION_SET = ['bx', 'blx']


class Instruction(object):
    def __init__(self, dwarf, instruction, context=None):
        """
        construct a dwarf instruction

        :param dwarf: the dwarf instance
        :param instruction: the capstone instruction object
        :param context: an optional context instance to retrieve jump address
        """
        self.id = instruction.id
        self.address = instruction.address
        self.size = instruction.size

        self.bytes = instruction.bytes

        self.groups = instruction.groups
        self.op_str = instruction.op_str
        self.mnemonic = instruction.mnemonic
        self.operands = instruction.operands

        # implicit regs read
        self.regs_read = instruction.regs_read

        self.reg_name = instruction.reg_name

        self.thumb = dwarf.arch == 'arm' and (
                ARM_GRP_THUMB in self.groups or ARM_GRP_THUMB1ONLY in self.groups or
                ARM_GRP_THUMB2 in self.groups or ARM_GRP_THUMB2DSP in self.groups)

        self.is_call = instruction.group(CS_GRP_CALL)
        self.is_jump = instruction.group(CS_GRP_JUMP)

        self.call_address = 0
        self.jump_address = 0

        self.should_change_arm_instruction_set = False

        if len(instruction.operands) > 0 and (self.is_jump or self.is_call):
            for op in instruction.operands:
                if op.type == CS_OP_IMM:
                    address = op.value.imm & int('0x' + (dwarf.pointer_size * 'ff'), 16)
                    self._set_jump_address(address)

                    if self.mnemonic in EXCHANGE_INSTRUCTION_SET:
                        self.should_change_arm_instruction_set = True
                elif op.type == CS_OP_REG:
                    if context is not None:
                        op_str = instruction.op_str
                        if op_str in context.__dict__:
                            address = context.__dict__[op_str] & int('0x' + (dwarf.pointer_size * 'ff'), 16)
                            self._set_jump_address(address)

                            if self.mnemonic in EXCHANGE_INSTRUCTION_SET:
                                if self.call_address % 2 == 0:
                                    self.should_change_arm_instruction_set = self.thumb
                                else:
                                    self.should_change_arm_instruction_set = not self.thumb
                elif op.type == CS_OP_MEM:
                    _temp = 0
                    if op.value.mem.base != 0:
                        reg = instruction.reg_name(op.value.mem.base)
                        if reg == 'rip' or reg == 'pc':
                            _temp = instruction.address
                    if op.value.mem.disp != 0:
                        _temp += op.value.mem.disp
                    self._set_jump_address(_temp)

        # resolve jump symbol and string
        self.symbol_name = None
        self.symbol_module = None
        self.string = None

        """if self.jump_address != 0:
            sym = dwarf.dwarf_api('getSymbolByAddress', self.jump_address)
            if sym is not None:
                self.symbol_name = sym['name']
                self.symbol_module = '-'
                if 'moduleName' in sym:
                    self.symbol_module = sym['moduleName']"""

    def _set_jump_address(self, jump):
        if self.is_call:
            self.call_address = jump
        elif self.is_jump:
            self.jump_address = jump
