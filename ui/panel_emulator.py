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
import capstone
from capstone import CS_OP_REG
from lib.emulator import STEP_MODE_NONE, STEP_MODE_SINGLE, STEP_MODE_FUNCTION, STEP_MODE_JUMP
from lib.range import Range
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QToolBar, QDialog, QLabel, QPushButton,
                             QComboBox)
from ui.dialog_emulator_configs import EmulatorConfigsDialog
from ui.dialog_input import InputDialog
from ui.panel_memory import MemoryPanel
from ui.widgets.disasm_view import DisassemblyView
from ui.widgets.list_view import DwarfListView
from unicorn import UcError, unicorn_const
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_FETCH, UC_MEM_WRITE


class EmulatorPanel(QWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app
        self.emulator = self.app.dwarf.emulator
        self.until_address = 0

        self._uc_user_arch = None
        self._uc_user_mode = None
        self._cs_user_arch = None
        self._cs_user_mode = None

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        self._toolbar_container = QHBoxLayout()
        self._toolbar = QToolBar()
        self._toolbar.addAction('Start', self.handle_start)
        self._toolbar.addAction('Step', self.handle_step)
        self._toolbar.addAction('Step next call', self.handle_step_next_call)
        self._toolbar.addAction('Step next jump', self.handle_step_next_jump)
        self._toolbar.addAction('Stop', self.handle_stop)
        self._toolbar.addAction('Clear', self.handle_clear)
        self._toolbar.addAction('Options', self.handle_options)
        self._toolbar_container.addWidget(self._toolbar)

        selection_layout = QHBoxLayout()
        selection_layout.setAlignment(Qt.AlignRight)
        self.cpu_selection = QComboBox(self)
        for v in unicorn_const.__dict__:
            if 'UC_ARCH_' in v:
                self.cpu_selection.addItem('_'.join(v.split('_')[2:]).lower(), unicorn_const.__dict__[v])
        self.cpu_selection.activated[str].connect(self._on_cpu_selection)
        self.mode_selection = QComboBox(self)
        for v in unicorn_const.__dict__:
            if 'UC_MODE_' in v:
                self.mode_selection.addItem('_'.join(v.split('_')[2:]).lower(), unicorn_const.__dict__[v])
        self.mode_selection.activated[str].connect(self._on_mode_selection)
        selection_layout.addWidget(self.cpu_selection)
        selection_layout.addWidget(self.mode_selection)
        self._toolbar_container.addLayout(selection_layout)

        layout.addLayout(self._toolbar_container)

        self.tabs = QTabWidget()
        self.assembly = DisassemblyView(self.app)
        self.assembly.display_jumps = False
        self.assembly.follow_jumps = False
        self.memory_table = MemoryPanel(self.app)
        self.memory_table._read_only = True
        self.tabs.addTab(self.assembly, 'Code')
        self.tabs.addTab(self.memory_table, 'Memory')

        layout.addWidget(self.tabs)

        self.ranges_list = DwarfListView(self.app)
        self.ranges_list.doubleClicked.connect(self.ranges_item_double_clicked)
        self._ranges_model = QStandardItemModel(0, 2)
        self._ranges_model.setHeaderData(0, Qt.Horizontal, 'Memory')
        self._ranges_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(1, Qt.Horizontal, 'Size')
        self._ranges_model.setHeaderData(1, Qt.Horizontal, Qt.AlignLeft, Qt.TextAlignmentRole)
        self.ranges_list.setModel(self._ranges_model)
        self.tabs.addTab(self.ranges_list, 'Ranges')

        self._access_list = DwarfListView(self.app)
        self._access_list.doubleClicked.connect(self.access_item_double_clicked)
        self._access_model = QStandardItemModel(0, 3)
        self._access_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._access_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._access_model.setHeaderData(1, Qt.Horizontal, 'Access')
        self._access_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._access_model.setHeaderData(2, Qt.Horizontal, 'Value')
        self._access_list.setModel(self._access_model)
        self.tabs.addTab(self._access_list, 'Access')

        layout.setSpacing(0)
        self.setLayout(layout)

        self.console = self.app.console.get_emu_console()

        self.emulator.onEmulatorSetup.connect(self.on_emulator_setup)
        self.emulator.onEmulatorStart.connect(self.on_emulator_start)
        self.emulator.onEmulatorStop.connect(self.on_emulator_stop)
        # self.emulator.onEmulatorStep.connect(self.on_emulator_step)
        self.emulator.onEmulatorHook.connect(self.on_emulator_hook)
        self.emulator.onEmulatorMemoryHook.connect(self.on_emulator_memory_hook)
        self.emulator.onEmulatorMemoryRangeMapped.connect(self.on_emulator_memory_range_mapped)
        self.emulator.onEmulatorLog.connect(self.on_emulator_log)

        self._require_register_result = None
        self._last_instruction_address = 0

    def _on_cpu_selection(self, cpu):
        self._uc_user_arch = unicorn_const.__dict__['UC_ARCH_' + cpu.upper()]
        self._cs_user_arch = capstone.__dict__['CS_ARCH_' + cpu.upper()]
        self._uc_user_mode = unicorn_const.__dict__['UC_MODE_' + self.mode_selection.itemText(
            self.mode_selection.currentIndex()).upper()]
        self._cs_user_mode = capstone.__dict__['CS_MODE_' + self.mode_selection.itemText(
            self.mode_selection.currentIndex()).upper()]

    def _on_mode_selection(self, mode):
        self._uc_user_mode = unicorn_const.__dict__['UC_MODE_' + mode.upper()]
        self._cs_user_mode = capstone.__dict__['CS_MODE_' + mode.upper()]
        self._uc_user_arch = unicorn_const.__dict__['UC_ARCH_' + self.cpu_selection.itemText(
            self.cpu_selection.currentIndex()).upper()]
        self._cs_user_arch = capstone.__dict__['CS_ARCH_' + self.cpu_selection.itemText(
            self.cpu_selection.currentIndex()).upper()]

    def resizeEvent(self, event):
        self.ranges_list.setFixedHeight((self.height() / 100) * 25)
        self.ranges_list.setFixedWidth((self.width() / 100) * 30)
        self._access_list.setFixedHeight((self.height() / 100) * 25)
        return super().resizeEvent(event)

    def handle_clear(self):
        self.ranges_list.clear()
        self._access_list.clear()
        self.assembly._lines.clear()
        self.assembly.viewport().update()
        # self.memory_table.setRowCount(0)
        self.console.clear()
        self.emulator.clean()

    def handle_options(self):
        EmulatorConfigsDialog.show_dialog(self.app.dwarf)

    def handle_start(self):
        ph = ''
        if self.until_address > 0:
            ph = hex(self.until_address)
        address, inp = InputDialog.input_pointer(self.app, input_content=ph, hint='pointer to last instruction')
        if address > 0:
            self.until_address = address
            self.app.console_panel.show_console_tab('emulator')
            self.emulator.emulate(self.until_address, user_arch=self._uc_user_arch,
                                  user_mode=self._uc_user_mode, cs_arch=self._cs_user_arch,
                                  cs_mode=self._cs_user_mode)
            # if err > 0:
            #    self.until_address = 0
            #    self.console.log('cannot start emulator. err: %d' % err)
            #    return

    def handle_step(self):
        self.app.console_panel.show_console_tab('emulator')

        try:
            self.emulator.emulate(step_mode=STEP_MODE_SINGLE, user_arch=self._uc_user_arch,
                                  user_mode=self._uc_user_mode, cs_arch=self._cs_user_arch,
                                  cs_mode=self._cs_user_mode)
        except self.emulator.EmulatorAlreadyRunningError:
            self.console.log('Emulator already running')
        except self.emulator.EmulatorSetupFailedError as error:
            self.until_address = 0
            self.console.log(error)

    def handle_step_next_call(self):
        self.app.console_panel.show_console_tab('emulator')

        try:
            self.emulator.emulate(
                step_mode=STEP_MODE_FUNCTION, user_arch=self._uc_user_arch,
                user_mode=self._uc_user_mode, cs_arch=self._cs_user_arch,
                cs_mode=self._cs_user_mode)
        except self.emulator.EmulatorAlreadyRunningError:
            self.console.log('Emulator already running')
        except self.emulator.EmulatorSetupFailedError as error:
            self.until_address = 0
            self.console.log(error)

    def handle_step_next_jump(self):
        self.app.console_panel.show_console_tab('emulator')

        try:
            self.emulator.emulate(
                step_mode=STEP_MODE_JUMP, user_arch=self._uc_user_arch,
                user_mode=self._uc_user_mode, cs_arch=self._cs_user_arch,
                cs_mode=self._cs_user_mode)
        except self.emulator.EmulatorAlreadyRunningError:
            self.console.log('Emulator already running')
        except self.emulator.EmulatorSetupFailedError as error:
            self.until_address = 0
            self.console.log(error)

    def handle_stop(self):
        self.emulator.stop()

    def on_emulator_hook(self, instruction):
        # @PinkiePonkie why setting context here (which is triggered each instruction) and later, set it again
        # in emulator_stop? step = double hit in set_context, running emulation on more than 1 instruction
        # doesn't need spam of set_context
        # self.app.context_panel.set_context(0, 2, self.emulator.current_context)

        # check if the previous hook is waiting for a register result
        if self._require_register_result is not None:
            row = 1
            if len(self._require_register_result) == 1:
                res = 'jump = %s' % (hex(self._require_register_result[0]))
            else:
                res = '%s = %s' % (
                    self._require_register_result[1], hex(self.emulator.uc.reg_read(self._require_register_result[0])))
            if len(self.assembly._lines) > 1:
                if self.assembly._lines[len(self.assembly._lines) - row] is None:
                    row = 2

                telescope = self.get_telescope(self.emulator.uc.reg_read(self._require_register_result[0]))
                if telescope is not None and telescope != 'None':
                    res += ' (' + telescope + ')'

                self.assembly._lines[len(self.assembly._lines) - row].string = res
                # invalidate
                self._require_register_result = None

        # check if the code jumped
        self._last_instruction_address = instruction.address

        self.assembly.add_instruction(instruction)

        # add empty line if jump
        if instruction.is_jump or instruction.is_call:
            self.assembly.add_instruction(None)
            self._require_register_result = [instruction.jump_address]
        else:
            # implicit regs read are notified later through mem access
            if len(instruction.regs_read) == 0:
                if len(instruction.operands) > 0:
                    for i in instruction.operands:
                        if i.type == CS_OP_REG:
                            self._require_register_result = [
                                i.value.reg,
                                instruction.reg_name(i.value.reg)
                            ]
                            break
        self.assembly.verticalScrollBar().setValue(len(self.assembly._lines))
        self.assembly.viewport().update()

        if instruction.is_call:
            range_ = Range(Range.SOURCE_TARGET, self.app.dwarf)
            if range_.init_with_address(instruction.address, require_data=False) > 0:
                if range_.base > instruction.call_address > range_.tail:
                    if self.emulator.step_mode == STEP_MODE_NONE:
                        self.emulator.stop()
                    action = JumpOutsideTheBoxDialog.show_dialog(self.app.dwarf)
                    if action == 0:
                        # step to jump
                        if self.emulator.step_mode != STEP_MODE_NONE:
                            self.handle_step()
                        else:
                            self.emulator.emulate(
                                self.until_address, user_arch=self._uc_user_arch,
                                user_mode=self._uc_user_mode, cs_arch=self._cs_user_arch,
                                cs_mode=self._cs_user_mode)
                    if action == 1:
                        # step to next jump
                        if self.emulator.step_mode != STEP_MODE_NONE:
                            self.handle_step_next_jump()
                        else:
                            self.emulator.emulate(
                                self.until_address, user_arch=self._uc_user_arch,
                                user_mode=self._uc_user_mode, cs_arch=self._cs_user_arch,
                                cs_mode=self._cs_user_mode)
                    elif action == 2:
                        # hook lr
                        hook_addr = instruction.address + instruction.size
                        if instruction.thumb:
                            hook_addr += 1
                        self.app.dwarf.hook_native(input_=hex(hook_addr))

    def on_emulator_log(self, log):
        self.app.console_panel.show_console_tab('emulator')
        self.console.log(log)

    def on_emulator_memory_hook(self, data):
        uc, access, address, value = data
        _address = QStandardItem()
        if self.ranges_list.uppercase_hex:
            if self.app.dwarf.pointer_size > 4:
                str_frmt = '0x{0:016X}'.format(address)
            else:
                str_frmt = '0x{0:08X}'.format(address)
        else:
            if self.app.dwarf.pointer_size > 4:
                str_frmt = '0x{0:016x}'.format(address)
            else:
                str_frmt = '0x{0:08x}'.format(address)
        _address.setText(str_frmt)
        _address.setTextAlignment(Qt.AlignCenter)

        _access = QStandardItem()
        if access == UC_MEM_READ:
            _access.setText('READ')
        elif access == UC_MEM_WRITE:
            _access.setText('WRITE')
        elif access == UC_MEM_FETCH:
            _access.setText('FETCH')
        _access.setTextAlignment(Qt.AlignCenter)

        _value = QStandardItem()
        _value.setText(str(value))

        self._access_model.appendRow([_address, _access, _value])

        res = None
        row = 1
        if len(self.assembly._lines) > 1:
            if self.assembly._lines[len(self.assembly._lines) - row] is None:
                row = 2
            if access == UC_MEM_READ:
                if self._require_register_result is not None:
                    if len(self._require_register_result) > 1:
                        res = '%s = %s' % (self._require_register_result[1], hex(value))
            else:
                if self.assembly._lines[len(self.assembly._lines) - row].string:
                    res = '%s, %s = %s' % (
                        self.assembly._lines[len(self.assembly._lines) - row].string, hex(address), hex(value))
                else:
                    res = '%s = %s' % (hex(address), hex(value))
            if res is not None:
                telescope = self.get_telescope(value)
                if telescope is not None and telescope != 'None':
                    res += ' (' + telescope + ')'
                # invalidate
                self._require_register_result = None
                self.assembly._lines[len(self.assembly._lines) - row].string = res

    def get_telescope(self, address):
        try:
            size = self.app.dwarf.pointer_size
            telescope = self.emulator.uc.mem_read(address, size)
            try:
                for i in range(len(telescope)):
                    if int(telescope[i]) == 0x0 and i != 0:
                        st = telescope.decode('utf8')
                        return st
                st = telescope.decode('utf8')
                if len(st) != size:
                    return '0x%s' % telescope.hex()
                while True:
                    telescope = self.emulator.uc.mem_read(address + size, 1)
                    if int(telescope) == 0x0:
                        break
                    st += telescope.decode('utf8')
                    size += 1
                return st
            except:
                return '0x%s' % telescope.hex()
        except UcError as e:
            # read from js
            telescope = self.app.dwarf.dwarf_api('getAddressTs', address)
            if telescope is None:
                return None
            telescope = str(telescope[1]).replace('\n', ' ')
            if len(telescope) > 50:
                telescope = telescope[:50] + '...'
            return telescope

    def on_emulator_memory_range_mapped(self, data):
        address, size = data
        _address = QStandardItem()
        if self.ranges_list.uppercase_hex:
            if self.app.dwarf.pointer_size > 4:
                str_frmt = '0x{0:016X}'.format(address)
            else:
                str_frmt = '0x{0:08X}'.format(address)
        else:
            if self.app.dwarf.pointer_size > 4:
                str_frmt = '0x{0:016x}'.format(address)
            else:
                str_frmt = '0x{0:08x}'.format(address)
        _address.setText(str_frmt)
        _address.setTextAlignment(Qt.AlignCenter)
        _size = QStandardItem()
        _size.setText("{0:,d}".format(int(size)))
        self._ranges_model.appendRow([_address, _size])

    def on_emulator_setup(self, data):
        user_arch = data[0]
        user_mode = data[1]
        if user_arch is not None and user_mode is not None:
            index = self.cpu_selection.findData(user_arch)
            self.cpu_selection.setCurrentIndex(index)
            index = self.mode_selection.findData(user_mode)
            self.mode_selection.setCurrentIndex(index)

    def on_emulator_start(self):
        pass

    def on_emulator_stop(self):
        self.app.context_panel.set_context(0, 2, self.emulator.current_context)
        # check if the previous hook is waiting for a register result
        if self._require_register_result is not None:
            row = 1
            if len(self._require_register_result) == 1:
                res = 'jump = %s' % (hex(self._require_register_result[0]))
            else:
                res = '%s = %s' % (
                    self._require_register_result[1], hex(self.emulator.uc.reg_read(self._require_register_result[0])))
                telescope = self.get_telescope(self.emulator.uc.reg_read(self._require_register_result[0]))
                if telescope is not None and telescope != 'None':
                    res += ' (' + telescope + ')'

            if len(self.assembly._lines) > 1:
                if self.assembly._lines[len(self.assembly._lines) - row] is None:
                    row = 2
                self.assembly._lines[len(self.assembly._lines) - row].string = res
                # invalidate
                self._require_register_result = None

    def ranges_item_double_clicked(self, model_index):
        row = self._ranges_model.itemFromIndex(model_index).row()
        if row != -1:
            item = self._ranges_model.item(row, 0).text()
            self.memory_table.read_memory(item)
            self.tabs.setCurrentIndex(1)

    def access_item_double_clicked(self, model_index):
        row = self._access_model.itemFromIndex(model_index).row()
        if row != -1:
            item = self._access_model.item(row, 0).text()
            self.memory_table.read_memory(item)
            self.tabs.setCurrentIndex(1)


class JumpOutsideTheBoxDialog(QDialog):
    def __init__(self, dwarf, parent=None):
        super(JumpOutsideTheBoxDialog, self).__init__(parent)
        self.dwarf = dwarf

        layout = QVBoxLayout(self)

        self.setMinimumWidth(500)

        layout.addWidget(QLabel('attempt to jump outside the current map\n'))

        self._step = False
        self._step_next_jump = False
        self._hook_lr = False

        buttons = QHBoxLayout()
        do_noting = QPushButton('do nothing')
        do_noting.clicked.connect(self.close)
        buttons.addWidget(do_noting)
        step = QPushButton('step into')
        step.clicked.connect(self.step)
        buttons.addWidget(step)
        step_next_jump = QPushButton('step to next jump')
        step_next_jump.clicked.connect(self.step_next_jump)
        buttons.addWidget(step_next_jump)
        hook_lr = QPushButton('hook lr')
        hook_lr.clicked.connect(self.hook_lr)
        buttons.addWidget(hook_lr)

        layout.addLayout(buttons)

    def step(self):
        self._step = True
        self.accept()

    def step_next_jump(self):
        self._step_next_jump = True
        self.accept()

    def hook_lr(self):
        self._hook_lr = True
        self.accept()

    @staticmethod
    def show_dialog(dwarf):
        dialog = JumpOutsideTheBoxDialog(dwarf)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            if dialog._step:
                return 0
            elif dialog._step_next_jump:
                return 1
            elif dialog._hook_lr:
                return 2
        return -1
