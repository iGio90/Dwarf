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
import binascii

from capstone import *

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from lib import utils
from lib.range import Range


VFP = "4ff4700001ee500fbff36f8f4ff08043e8ee103a"


class Emulator(object):
    def __init__(self, dwarf):
        self.dwarf = dwarf

        self.cs = None
        self.uc = None

        self.context = None
        self.thumb = False
        self.end_ptr = 0

    def api(self, parts):
        """
        expose api to js side for allowing emulator interaction while scripting
        :param parts: arr -> cmd api split by ":::"
        :return: the result from the api
        """
        cmd = parts[0]
        if cmd == 'setup':
            self.dwarf.log(self.setup(parts[1]))
        elif cmd == 'start':
            self.dwarf.log(self.start(parts[1]))

    def hook_code(self, uc, address, size, user_data):
        # hold address for thumb
        s_address = address
        if self.thumb:
            s_address = s_address | 1
        for i in self.cs.disasm(bytes(uc.mem_read(address, size)), address):
            print("0x%x:\t%s\t%s" % (s_address, i.mnemonic, i.op_str))

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x"
                  % (address, size, value))
        else:
            print(">>> Memory is being READ at 0x%x, data size = %u, data value = 0x%s"
                  % (address, size, binascii.hexlify(self.uc.mem_read(address, size)).decode('utf8')))

    def hook_unmapped(self, uc, access, address, size, value, user_data):
        print(">>> Unmapped memory at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        err = self.map_range(address)
        if err > 0:
            print('error %d mapping range for %s' % (err, hex(address)))
        else:
            self.start(self.end_ptr)

    def map_range(self, address):
        print('mapping -> ' + hex(address))

        range = Range(self.dwarf)
        if range.init_with_address(address) > 0:
            return 300
        try:
            self.uc.mem_map(range.base, range.size)
        except Exception as e:
            self.dwarf.log(e)
            return 301

        try:
            self.uc.mem_write(range.base, range.data)
        except Exception as e:
            self.dwarf.log(e)
            return 302

        return 0

    def setup(self, tid=0):
        if tid == 0:
            # get current context tid if none provided
            tid = self.dwarf.context_tid

        # make sure it's int
        tid = int(tid)
        self.context = None

        if str(tid) in self.dwarf.contexts:
            self.context = self.dwarf.contexts[str(tid)]

        if self.context is None:
            return 1

        if self.dwarf.arch == 'arm':
            self.thumb = self.context.pc.thumb
            if self.thumb:
                self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

                # Enable VFP instr
                self.uc.mem_map(0x1000, 1024)
                self.uc.mem_write(0x1000, binascii.unhexlify(VFP))
                self.uc.emu_start(0x1000 | 1, 0x1000 + len(VFP))
                self.uc.mem_unmap(0x1000, 1024)

            else:
                self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        elif self.dwarf.arch == 'arm64':
            self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            # unsupported arch
            return 5

        err = self.map_range(self.context.pc.value)
        if err > 0:
            return err
        if self.dwarf.arch == 'arm':
            self.uc.reg_write(UC_ARM_REG_R0, self.context.r0.value)
            self.uc.reg_write(UC_ARM_REG_R1, self.context.r1.value)
            self.uc.reg_write(UC_ARM_REG_R2, self.context.r2.value)
            self.uc.reg_write(UC_ARM_REG_R3, self.context.r3.value)
            self.uc.reg_write(UC_ARM_REG_R4, self.context.r4.value)
            self.uc.reg_write(UC_ARM_REG_R5, self.context.r5.value)
            self.uc.reg_write(UC_ARM_REG_R6, self.context.r6.value)
            self.uc.reg_write(UC_ARM_REG_R7, self.context.r7.value)
            self.uc.reg_write(UC_ARM_REG_R8, self.context.r8.value)
            self.uc.reg_write(UC_ARM_REG_R9, self.context.r9.value)
            self.uc.reg_write(UC_ARM_REG_R10, self.context.r10.value)
            self.uc.reg_write(UC_ARM_REG_R11, self.context.r11.value)
            self.uc.reg_write(UC_ARM_REG_R12, self.context.r12.value)
            self.uc.reg_write(UC_ARM_REG_PC, self.context.pc.value)
            self.uc.reg_write(UC_ARM_REG_SP, self.context.sp.value)
            self.uc.reg_write(UC_ARM_REG_LR, self.context.lr.value)
        elif self.dwarf.arch == 'arm64':
            # todo
            pass

        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.hook_mem_access)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED |
                         UC_HOOK_MEM_WRITE_UNMAPPED |
                         UC_HOOK_MEM_READ_UNMAPPED,
                         self.hook_unmapped)
        return err

    def start(self, until):
        self.end_ptr = utils.parse_ptr(until)
        if self.context is None:
            err = self.setup()
            if err > 0:
                return 200 + err
        if self.uc._arch == UC_ARCH_ARM:
            address = self.uc.reg_read(UC_ARM_REG_PC)
        elif self.uc._arch == UC_ARCH_ARM64:
            address = self.uc.reg_read(UC_ARM64_REG_PC)
        else:
            # unsupported arch
            return 2
        if self.thumb:
            address = address | 1
        print('starting -> ' + hex(address))
        print('until -> ' + hex(self.end_ptr))
        try:
            self.uc.emu_start(address, self.end_ptr)
            return 0
        except UcError as err:
            self.uc.emu_stop()
            print(err)

            return 0
        except Exception as e:
            self.uc.emu_stop()
            print(e)
            return 5
