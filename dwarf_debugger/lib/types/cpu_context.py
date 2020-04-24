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
from dwarf_debugger.lib.types.cpu_register import CpuRegister


class CpuContext(object):
    """ Base Cpucontext
    """
    __slots__ = []

    def __eq__(self, value):
        if self.__class__ != value.__class__:
            return False

        slots = self.__class__.__slots__
        if isinstance(slots, str):
            slots = [slots]

        return all(getattr(self, x) == getattr(value, x) for x in slots)

    def __getattribute__(self, name):
        ret_value = super().__getattribute__(name)
        if isinstance(ret_value, CpuRegister):
            ret_value = ret_value.value

        return ret_value


class X86CpuContext(CpuContext):
    """ x86 CpuContext

        + eax: General-Purpose Register
        + ebx: General-Purpose Register
        + ecx: General-Purpose Register
        + edx: General-Purpose Register
        + esi: General-Purpose Register
        + edi: General-Purpose Register
        + esp: Stack Pointer
        + ebp: Base Pointer
        + eip: Instruction Pointer
    """
    __slots__ = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eip']

    def __init__(self, context=None):
        _descs = [
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'Stack Pointer',
            'Base Pointer',
            'Instruction Pointer',
        ]

        for i, slot in enumerate(self.__slots__):
            setattr(self, slot, CpuRegister(slot, 0, _descs[i]))

    def getStackPointer(self):
        return getattr(self, 'esp', 0)

    def getInstructionPointer(self):
        return getattr(self, 'eip', 0xffffffff)

    def getBasePointer(self):
        return getattr(self, 'ebp', 0xffffffff)


class X64CpuContext(CpuContext):
    """ x64 CpuContext

        + rax: General-Purpose Register
        + rbx: General-Purpose Register
        + rcx: General-Purpose Register
        + rdx: General-Purpose Register
        + rsi: General-Purpose Register
        + rdi: General-Purpose Register
        + r8: General-Purpose Register
        + r9: General-Purpose Register
        + r10: General-Purpose Register
        + r11: General-Purpose Register
        + r12: General-Purpose Register
        + r13: General-Purpose Register
        + r14: General-Purpose Register
        + r15: General-Purpose Register
        + rsp: Stack Pointer
        + rbp: Base Pointer
        + rip: Instruction Pointer
    """
    __slots__ = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9',
                 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsp', 'rbp', 'rip']

    def __init__(self, context=None):
        _descs = [
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'Stack Pointer',
            'Base Pointer',
            'Instruction Pointer',
        ]

        for i, slot in enumerate(self.__slots__):
            setattr(self, slot, CpuRegister(slot, 0, _descs[i]))

    def getStackPointer(self):
        return getattr(self, 'rsp', 0)

    def getInstructionPointer(self):
        return getattr(self, 'rip', 0xffffffff)

    def getBasePointer(self):
        return getattr(self, 'rbp', 0xffffffff)


class ARMCpuContext(CpuContext):
    """ ARM CpuContext

        + cspr:
        + pc: Program Counter
        + sp: Stack Pointer
        + r1: General-Purpose Register
        + r2: General-Purpose Register
        + r3: General-Purpose Register
        + r4: General-Purpose Register
        + r5: General-Purpose Register
        + r6: General-Purpose Register
        + r7: General-Purpose Register
        + r8: General-Purpose Register
        + r9: General-Purpose Register
        + r10: General-Purpose Register
        + r11: General-Purpose Register
        + r12: General-Purpose Register
        + lr:
    """
    __slots__ = ['cpsr', 'pc', 'sp', 'r1', 'r2', 'r3', 'r4',
                 'r5', 'r6', 'r7' 'r8', 'r9', 'r10', 'r11', 'r12', 'lr']

    def __init__(self, context=None):
        _descs = [
            '',  # ???
            'Program Counter',
            'Stack Pointer',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            ''  # ???
        ]

        for i, slot in enumerate(self.__slots__):
            setattr(self, slot, CpuRegister(slot, 0, _descs[i]))

    def getStackPointer(self):
        return getattr(self, 'sp', 0)

    def getInstructionPointer(self):
        return getattr(self, 'pc', 0xffffffff)  # ???

    def getBasePointer(self):
        return getattr(self, 'lr', 0xffffffff)  # ???


class ARM64CpuContext(CpuContext):
    """ ARM CpuContext

        + cspr:
        + pc: Program Counter
        + sp: Stack Pointer
        + r1: General-Purpose Register
        + r2: General-Purpose Register
        + r3: General-Purpose Register
        + r4: General-Purpose Register
        + r5: General-Purpose Register
        + r6: General-Purpose Register
        + r7: General-Purpose Register
        + r8: General-Purpose Register
        + r9: General-Purpose Register
        + r10: General-Purpose Register
        + r11: General-Purpose Register
        + r12: General-Purpose Register
        + lr:
    """
    __slots__ = ['cpsr', 'pc', 'sp', 'r1', 'r2', 'r3', 'r4',
                 'r5', 'r6', 'r7' 'r8', 'r9', 'r10', 'r11', 'r12', 'lr']

    def __init__(self, context=None):
        _descs = [
            '',  # ???
            'Program Counter',
            'Stack Pointer',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            'General-Purpose Register',
            ''  # ???
        ]

        for i, slot in enumerate(self.__slots__):
            setattr(self, slot, CpuRegister(slot, 0, _descs[i]))

    def getStackPointer(self):
        return getattr(self, 'sp', 0)

    def getInstructionPointer(self):
        return getattr(self, 'pc', 0xffffffff)  # ???

    def getBasePointer(self):
        return getattr(self, 'lr', 0xffffffff)  # ???
