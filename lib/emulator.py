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
import time

from importlib._bootstrap import spec_from_loader, module_from_spec
from importlib._bootstrap_external import SourceFileLoader

import unicorn
from capstone import *
from lib import utils, prefs
from lib.instruction import Instruction
from lib.range import Range
from threading import Thread


VFP = "4ff4700001ee500fbff36f8f4ff08043e8ee103a"


class Emulator(object):
    def __init__(self, dwarf):
        self.dwarf = dwarf

        self.cs = None
        self.uc = None

        self.context = None
        self.thumb = False
        self.end_ptr = 0

        self.stepping = [False, False]
        self._running = False
        self._current_instruction = 0
        self._current_cpu_mode = 0

        # configurations
        self.callbacks_path = None
        self.callbacks = None
        self.instructions_delay = 0

    def __setup(self):
        if self.dwarf.arch == 'arm':
            unicorn_consts = unicorn.arm_const
            self.thumb = self.context.pc.thumb
            if self.thumb:
                self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
                self._current_cpu_mode = unicorn.UC_MODE_THUMB
                # Enable VFP instr
                self.uc.mem_map(0x1000, 1024)
                self.uc.mem_write(0x1000, binascii.unhexlify(VFP))
                self.uc.emu_start(0x1000 | 1, 0x1000 + len(VFP))
                self.uc.mem_unmap(0x1000, 1024)
            else:
                self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
                self._current_cpu_mode = unicorn.UC_MODE_ARM
        elif self.dwarf.arch == 'arm64':
            unicorn_consts = unicorn.arm64_const
            self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_LITTLE_ENDIAN)
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

            self._current_cpu_mode = unicorn.UC_MODE_LITTLE_ENDIAN
        else:
            # unsupported arch
            return 5

        # enable capstone details
        self.cs.detail = True

        err = self.map_range(self.context.pc.value)
        if err > 0:
            return err

        # setup context

        uc_registers = {}
        for v in unicorn_consts.__dict__:
            if '_REG_' in v:
                reg = v.lower().split('_')[-1]
                uc_registers[reg] = unicorn.arm64_const.__dict__[v]

        for k in self.context.__dict__:
            self.uc.reg_write(uc_registers[k], self.context.__dict__[k].value)

        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE | unicorn.UC_HOOK_MEM_READ, self.hook_mem_access)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_FETCH_UNMAPPED |
                         unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                         unicorn.UC_HOOK_MEM_READ_UNMAPPED,
                         self.hook_unmapped)
        return err

    def __start(self, address, until):
        try:
            self._running = True
            self.uc.emu_start(address, until)
        except unicorn.UcError as e:
            self.log_to_ui('[*] error: ' + str(e))
        except Exception as e:
            self.log_to_ui('[*] error: ' + str(e))
        self._running = False
        self.dwarf.get_bus().emit('emulator_stop')

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

    def clean(self):
        if self._running:
            return 1

        self.stepping = [False, False]
        self._current_instruction = 0
        self._current_cpu_mode = 0

        return self.__setup()

    def hook_code(self, uc, address, size, user_data):
        self._current_instruction = address

        # if it's arm we query the cpu mode to detect switches between arm and thumb and set capstone mode if needed
        if self.cs.arch == CS_ARCH_ARM:
            mode = self.uc.query(unicorn.UC_QUERY_MODE)
            if self._current_cpu_mode != mode:
                self._current_cpu_mode = mode
                self.cs.mode = self._current_cpu_mode
                self.thumb = self._current_cpu_mode == unicorn.UC_MODE_THUMB

        if self.stepping[0]:
            if self.stepping[1]:
                uc.emu_stop()
                return
            else:
                self.stepping[1] = True

        for i in self.cs.disasm(bytes(uc.mem_read(address, size)), address):
            instruction = Instruction(self.dwarf, i)
            self.dwarf.get_bus().emit('emulator_hook', uc, instruction)
            if self.callbacks is not None:
                try:
                    self.callbacks.hook_code(self, instruction, address, size)
                except:
                    # hook code not implemented in callbacks
                    pass

        time.sleep(self.instructions_delay)

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        v = value
        if access == unicorn.UC_MEM_READ:
            v = int.from_bytes(uc.mem_read(address, size), 'little')
        self.dwarf.get_bus().emit('emulator_memory_hook', uc, access, address, v)
        if self.callbacks is not None:
            try:
                self.callbacks.hook_memory_access(self, access, address, size, v)
            except:
                # hook code not implemented in callbacks
                pass

    def hook_unmapped(self, uc, access, address, size, value, user_data):
        self.log_to_ui("[*] Trying to access an unmapped memory address at 0x%x" % address)
        err = self.map_range(address)
        if err > 0:
            self.log_to_ui('[*] Error %d mapping range at %s' % (err, hex(address)))
            return False
        return True

    def invalida_configurations(self):
        self.callbacks_path = self.dwarf.get_prefs().get(prefs.EMULATOR_CALLBACKS_PATH, '')
        self.instructions_delay = self.dwarf.get_prefs().get(prefs.EMULATOR_INSTRUCTIONS_DELAY, 0.5)

    def map_range(self, address):
        range = Range(Range.SOURCE_TARGET, self.dwarf)
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

        self.log_to_ui("[*] Mapped %d at 0x%x" % (range.size, range.base))
        self.dwarf.get_bus().emit('emulator_memory_range_mapped', range.base, range.size)
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

        return self.__setup()

    def start(self, until=0):
        if self._running:
            return 10

        if until > 0:
            self.end_ptr = utils.parse_ptr(until)
            if self.end_ptr == 0:
                # invalid end pointer
                return 1
        if self.context is None:
            err = self.setup()
            if err > 0:
                return 200 + err

        # calculate the start address
        address = self._current_instruction
        if address == 0:
            if self.uc._arch == unicorn.UC_ARCH_ARM:
                address = self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            elif self.uc._arch == unicorn.UC_ARCH_ARM64:
                address = self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
            else:
                # unsupported arch
                return 2

        if until > 0:
            self.log_to_ui('[*] start emulation from %s to %s' % (hex(address), hex(self.end_ptr)))
        else:
            self.log_to_ui('[*] stepping %s' % hex(address))
        self.dwarf.get_bus().emit('emulator_start')

        if self.thumb:
            address = address | 1

        # invalidate prefs before start
        self.invalida_configurations()

        # load callbacks if needed
        if self.callbacks_path is not None and self.callbacks_path != '':
            try:
                spec = spec_from_loader("callbacks", SourceFileLoader("callbacks", self.callbacks_path))
                self.callbacks = module_from_spec(spec)
                spec.loader.exec_module(self.callbacks)
            except Exception as e:
                self.log_to_ui('[*] failed to load callbacks: %s' % str(e))
                # reset callbacks path
                self.dwarf.get_prefs().put(prefs.EMULATOR_CALLBACKS_PATH, '')
                self.callbacks_path = ''
                self.callbacks = None
        else:
            self.callbacks = None

        # until is 0 (i.e we are stepping)
        if until == 0:
            self.stepping = [True, False]
            self.end_ptr = address + (self.dwarf.pointer_size * 2)
        else:
            self.stepping = [False, False]
        Thread(target=self.__start, args=(address, self.end_ptr)).start()
        return 0

    def stop(self):
        if self._running:
            self.uc.emu_stop()

    def log_to_ui(self, what):
        self.dwarf.get_bus().emit('emulator_log', what)
