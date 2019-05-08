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

from threading import Thread

from PyQt5.QtCore import QObject, pyqtSignal, QThread
from PyQt5.QtWidgets import QApplication

from importlib._bootstrap import spec_from_loader, module_from_spec
from importlib._bootstrap_external import SourceFileLoader

import unicorn
from capstone import (Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32,
                      CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
                      CS_MODE_LITTLE_ENDIAN)
from lib import utils, prefs
from lib.context import EmulatorContext
from lib.instruction import Instruction
from lib.range import Range

from lib.prefs import Prefs

VFP = "4ff4700001ee500fbff36f8f4ff08043e8ee103a"


class Emulator(QThread):
    class EmulatorSetupFailedError(Exception):
        """ Setup Failed
        """

    class EmulatorAlreadyRunningError(Exception):
        """ isrunning
        """

    onEmulatorStart = pyqtSignal(name='onEmulatorStart')
    onEmulatorStop = pyqtSignal(name='onEmulatorStop')
    onEmulatorStep = pyqtSignal(name='onEmulatorStep')
    onEmulatorHook = pyqtSignal(Instruction, name='onEmulatorHook')
    onEmulatorMemoryHook = pyqtSignal(list, name='onEmulatorMemoryHook')
    onEmulatorMemoryRangeMapped = pyqtSignal(
        list, name='onEmulatorMemoryRangeMapped')

    onEmulatorLog = pyqtSignal(str, name='onEmulatorLog')

    def __init__(self, dwarf):
        super(Emulator, self).__init__()

        self.setTerminationEnabled(True)
        self.dwarf = dwarf
        self._prefs = Prefs()

        self._setup_done = False
        self._blacklist_regs = []

        self.cs = None
        self.uc = None

        self.context = None
        self.thumb = False
        self.end_ptr = 0

        self.current_context = None

        self.stepping = [False, False]
        self._current_instruction = 0
        self._current_cpu_mode = 0

        self._request_stop = False

        # configurations
        self.callbacks_path = None
        self.callbacks = None
        self.instructions_delay = 0

        self._start_address = 0
        self._end_address = 0

    def setup_arm(self):
        self.thumb = self.context.pc.thumb
        if self.thumb:
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM,
                                    unicorn.UC_MODE_THUMB)
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

    def setup_arm64(self):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_LITTLE_ENDIAN)
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self._current_cpu_mode = unicorn.UC_MODE_LITTLE_ENDIAN

    def setup_x86(self):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def setup_x64(self):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)

    def _setup(self):
        if self.dwarf.arch == 'arm':
            self.setup_arm()
        elif self.dwarf.arch == 'arm64':
            self.setup_arm64()
        elif self.dwarf.arch == 'ia32':
            self.setup_x86()
        elif self.dwarf.arch == 'x64':
            self.setup_x64()
        else:
            # unsupported arch
            raise self.EmulatorSetupFailedError('Unsupported arch')

        if not self.uc or not self.cs:
            raise self.EmulatorSetupFailedError('Unicorn or Capstone missing')

        # enable capstone details
        if self.cs is not None:
            self.cs.detail = True

        err = self.map_range(self.context.pc.value)
        if err:
            raise self.EmulatorSetupFailedError('Mapping failed')

        self.current_context = EmulatorContext(self.dwarf)
        for reg in self.current_context._unicorn_registers:
            if reg in self.context.__dict__:
                if reg not in self._blacklist_regs:
                    self.uc.reg_write(self.current_context._unicorn_registers[reg], self.context.__dict__[reg].value)

        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE | unicorn.UC_HOOK_MEM_READ,
                         self.hook_mem_access)
        self.uc.hook_add(
            unicorn.UC_HOOK_MEM_FETCH_UNMAPPED |
            unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
            unicorn.UC_HOOK_MEM_READ_UNMAPPED, self.hook_unmapped)
        self.current_context.set_context(self.uc)
        return True

    def run(self):
        # dont call this func
        if not self._setup_done:
            return
        try:
            self.uc.emu_start(self._start_address, 0xffffffffffffffff)  # end is handled in hook_code
        except unicorn.UcError as e:
            self.log_to_ui('[*] error: ' + str(e))
        except Exception as e:
            self.log_to_ui('[*] error: ' + str(e))

        self._setup_done = False
        self.onEmulatorStop.emit()

    def api(self, parts):
        """
        expose api to js side for allowing emulator interaction while scripting
        :param parts: arr -> cmd api split by ":::"
        :return: the result from the api
        """
        cmd = parts[0]
        if cmd == 'clean':
            return self.clean()
        elif cmd == 'setup':
            return self.setup(parts[1])
        elif cmd == 'start':
            return self.emulate(parts[1])

    def clean(self):
        if self.isRunning():
            return False

        self.stepping = [False, False]
        self._current_instruction = 0
        self._current_cpu_mode = 0

        return self._setup()

    def hook_code(self, uc, address, size, user_data):
        # QApplication.processEvents()
        if self._request_stop:
            self.log_to_ui('Error: Emulator stopped - reached end')
            self.stop()
            return

        if self._current_instruction == address:
            # we should never be here or it is looping
            self.log_to_ui('Error: Emulator stopped - looping')
            self.stop()

        self._current_instruction = address

        # check if pc/eip is end_ptr
        pc = 0  # address should be pc too ???
        if self.dwarf.arch == 'arm':
            pc = uc.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
        elif self.dwarf.arch == 'arm64':
            pc = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        elif self.dwarf.arch == 'ia32':
            pc = uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
        elif self.dwarf.arch == 'x64':
            pc = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)

        if pc == self._end_address:
            self._request_stop = True

        # set the current context
        self.current_context.set_context(uc)

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

        try:
            try:
                assembly = self.cs.disasm(bytes(uc.mem_read(address, size)), address)
            except:
                self.log_to_ui('Error: Emulator stopped - disasm')
                self.stop()

            for i in assembly:
                # QApplication.processEvents()
                instruction = Instruction(self.dwarf, i)
                self.onEmulatorHook.emit(instruction)
                if self.callbacks is not None:
                    try:
                        self.callbacks.hook_code(self, instruction, address, size)
                    except:
                        # hook code not implemented in callbacks
                        pass

            # time.sleep(self.instructions_delay)
        except:
            self.log_to_ui('Error: Emulator stopped')
            self.stop()

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        v = value
        if access == unicorn.UC_MEM_READ:
            v = int.from_bytes(uc.mem_read(address, size), 'little')
        self.onEmulatorMemoryHook.emit([uc, access, address, v])
        if self.callbacks is not None:
            try:
                self.callbacks.hook_memory_access(self, access, address, size,
                                                  v)
            except:
                # hook code not implemented in callbacks
                pass

    def hook_unmapped(self, uc, access, address, size, value, user_data):
        self.log_to_ui(
            "[*] Trying to access an unmapped memory address at 0x%x" %
            address)
        err = self.map_range(address)
        if err > 0:
            self.log_to_ui(
                '[*] Error %d mapping range at %s' % (err, hex(address)))
            return False
        return True

    def invalida_configurations(self):
        self.callbacks_path = self._prefs.get(prefs.EMULATOR_CALLBACKS_PATH, '')
        self.instructions_delay = self._prefs.get(prefs.EMULATOR_INSTRUCTIONS_DELAY, 0)

    def map_range(self, address):
        range_ = Range(Range.SOURCE_TARGET, self.dwarf)
        if range_.init_with_address(address) > 0:
            return 300
        try:
            self.uc.mem_map(range_.base, range_.size)
        except Exception as e:
            self.dwarf.log(e)
            return 301

        try:
            self.uc.mem_write(range_.base, range_.data)
        except Exception as e:
            self.dwarf.log(e)
            return 302

        self.log_to_ui("[*] Mapped %d at 0x%x" % (range_.size, range_.base))
        self.onEmulatorMemoryRangeMapped.emit([range_.base, range_.size])

        return 0

    def setup(self, tid=0):
        if tid == 0:
            # get current context tid if none provided
            tid = self.dwarf.context_tid

        # make sure it's int < pp: why make sure its int and then using str(tid) later??
        #                       when calling from api its str
        if isinstance(tid, str):
            try:
                tid = int(tid)
            except ValueError:
                return False

        if not isinstance(tid, int):
            return False

        self.context = None

        if str(tid) in self.dwarf.contexts:
            self.context = self.dwarf.contexts[str(tid)]

        if self.context is None:
            return False

        try:
            self._setup()
        except self.EmulatorSetupFailedError:
            return False

        return True

    def start(self, priority=QThread.HighPriority):
        # dont call this func
        if not self._setup_done:
            return
        return super().start(priority=priority)

    def emulate(self, until=0):
        if self.isRunning():
            raise self.EmulatorAlreadyRunningError()

        if isinstance(until, str):
            try:
                until = int(until, 16)
            except ValueError:
                until = 0

        if until and isinstance(until, int):
            self.end_ptr = utils.parse_ptr(until)
            if self.end_ptr == 0:
                # invalid end pointer
                raise self.EmulatorSetupFailedError('Invalid EndPtr')

        if self.context is None:
            if not self.setup():
                raise self.EmulatorSetupFailedError('Setup failed')

        # calculate the start address
        address = self._current_instruction
        if address == 0:
            if self.uc._arch == unicorn.UC_ARCH_ARM:
                address = self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            elif self.uc._arch == unicorn.UC_ARCH_ARM64:
                address = self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
            elif self.uc._arch == unicorn.UC_ARCH_X86 and self.uc._mode == unicorn.UC_MODE_32:
                address = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            elif self.uc._arch == unicorn.UC_ARCH_X86 and self.uc._mode == unicorn.UC_MODE_64:
                address = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
            else:
                raise self.EmulatorSetupFailedError('Unsupported arch')

        if until > 0:
            self.log_to_ui('[*] start emulation from %s to %s' % (hex(address), hex(self.end_ptr)))
        else:
            self.log_to_ui('[*] stepping %s' % hex(address))
        self.onEmulatorStart.emit()

        if self.thumb:
            address = address | 1

        # invalidate prefs before start
        self.invalida_configurations()

        # load callbacks if needed
        if self.callbacks_path is not None and self.callbacks_path != '':
            try:
                spec = spec_from_loader(
                    "callbacks",
                    SourceFileLoader("callbacks", self.callbacks_path))
                self.callbacks = module_from_spec(spec)
                spec.loader.exec_module(self.callbacks)
            except Exception as e:
                self.log_to_ui('[*] failed to load callbacks: %s' % str(e))
                # reset callbacks path
                self._prefs.put(prefs.EMULATOR_CALLBACKS_PATH, '')
                self.callbacks_path = ''
                self.callbacks = None
        else:
            self.callbacks = None

        # until is 0 (i.e we are stepping)
        if until == 0:
            self.stepping = [True, False]
            # self.end_ptr = address + (self.dwarf.pointer_size * 2) stupid
        else:
            self.stepping = [False, False]

        self._start_address = address
        self._end_address = self.end_ptr
        self._setup_done = True
        self.start()

    def stop(self):
        if self.isRunning():
            self.uc.emu_stop()

    def log_to_ui(self, what):
        self.onEmulatorLog.emit(what)
