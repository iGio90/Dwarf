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
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QToolBar)

from ui.dialog_emulator_configs import EmulatorConfigsDialog
from ui.dialog_input import InputDialog
from ui.panel_memory import MemoryPanel

from capstone import CS_OP_REG
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_FETCH, UC_MEM_WRITE

from ui.list_view import DwarfListView
from ui.disasm_view import DisassemblyView


class EmulatorPanel(QWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app
        self.emulator = self.app.dwarf.emulator
        self.until_address = 0

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        self._toolbar = QToolBar()
        self._toolbar.addAction('Start', self.handle_start)
        self._toolbar.addAction('Step', self.handle_step)
        self._toolbar.addAction('Stop', self.handle_stop)
        self._toolbar.addAction('Clean', self.handle_clean)
        self._toolbar.addAction('Options', self.handle_options)

        layout.addWidget(self._toolbar)

        self.tabs = QTabWidget()
        self.assembly = DisassemblyView(self.app)
        self.assembly.display_jumps = False
        self.assembly.follow_jumps = False
        self.memory_table = MemoryPanel(self.app)
        self.memory_table._read_only = True
        self.tabs.addTab(self.assembly, 'Code')
        self.tabs.addTab(self.memory_table, 'Memory')

        layout.addWidget(self.tabs)

        h_box = QHBoxLayout()
        self.ranges_list = DwarfListView(self.app)
        self.ranges_list.doubleClicked.connect(self.ranges_item_double_clicked)
        self._ranges_model = QStandardItemModel(0, 2)
        self._ranges_model.setHeaderData(0, Qt.Horizontal, 'Memory')
        self._ranges_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(1, Qt.Horizontal, 'Size')
        self.ranges_list.setModel(self._ranges_model)

        self._access_list = DwarfListView(self.app)
        self._access_list.doubleClicked.connect(self.access_item_double_clicked)
        self._access_model = QStandardItemModel(0, 3)
        self._access_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._access_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._access_model.setHeaderData(1, Qt.Horizontal, 'Access')
        self._access_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._access_model.setHeaderData(2, Qt.Horizontal, 'Value')
        self._access_list.setModel(self._access_model)
        h_box.addWidget(self.ranges_list)
        h_box.addWidget(self._access_list)

        layout.addLayout(h_box)
        self.setLayout(layout)

        self.console = self.app.console.get_emu_console()

        self.emulator.onEmulatorStart.connect(self.on_emulator_start)
        self.emulator.onEmulatorStop.connect(self.on_emulator_stop)
        # self.emulator.onEmulatorStep.connect(self.on_emulator_step)
        self.emulator.onEmulatorHook.connect(self.on_emulator_hook)
        self.emulator.onEmulatorMemoryHook.connect(self.on_emulator_memory_hook)
        self.emulator.onEmulatorMemoryRangeMapped.connect(self.on_emulator_memory_range_mapped)
        self.emulator.onEmulatorLog.connect(self.on_emulator_log)

        self._require_register_result = None
        self._last_instruction_address = 0

    def resizeEvent(self, event):
        self.ranges_list.setFixedHeight((self.height() / 100) * 25)
        self.ranges_list.setFixedWidth((self.width() / 100) * 30)
        self._access_list.setFixedHeight((self.height() / 100) * 25)
        return super().resizeEvent(event)

    def handle_clean(self):
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
        address, inp = InputDialog.input_pointer(self.app, input_content=ph,
                                                 hint='pointer to last instruction')
        if address > 0:
            self.until_address = address
            self.emulator.emulate(self.until_address)
            # if err > 0:
            #    self.until_address = 0
            #    self.console.log('cannot start emulator. err: %d' % err)
            #    return

    def handle_step(self):
        try:
            result = self.emulator.emulate()
            if not result:
                self.console.log('Emulation failed')
        except self.emulator.EmulatorAlreadyRunningError:
            self.console.log('Emulator already runnging')
        except self.emulator.EmulatorSetupFailedError as error:
            self.until_address = 0
            self.console.log(error)

    def handle_stop(self):
        self.emulator.stop()

    def on_emulator_hook(self, instruction):
        self.app.context_panel.set_context(0, 2, self.emulator.current_context)
        # check if the previous hook is waiting for a register result
        if self._require_register_result is not None:
            row = 1
            res = '%s = %s' % (self._require_register_result[1],
                               hex(self.emulator.uc.reg_read(self._require_register_result[0])))
            if len(self.assembly._lines) > 1:
                if self.assembly._lines[len(self.assembly._lines) - row] is None:
                    row = 2
                self.assembly._lines[len(self.assembly._lines) - row].string = res
                # invalidate
                self._require_register_result = None

        # check if the code jumped
        self._last_instruction_address = instruction.address

        self.assembly.add_instruction(instruction)

        # add empty line if jump
        if instruction.is_jump:
            self.assembly.add_instruction(None)

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

    def on_emulator_log(self, log):
        self.app.console_panel.show_console_tab('emulator')
        self.console.log(log)

    def on_emulator_memory_hook(self, data):
        uc, access, address, value = data
        _address = QStandardItem()
        str_frmt = ''
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
                    res = '%s = %s' % (self._require_register_result[1], hex(value))
            else:
                if self.assembly._lines[len(self.assembly._lines) - row].string:
                    res = '%s, %s = %s' % (self.assembly._lines[len(self.assembly._lines) - row].string, hex(address), hex(value))
                else:
                    res = '%s = %s' % (hex(address), hex(value))
            if res is not None:
                # invalidate
                self._require_register_result = None

                self.assembly._lines[len(self.assembly._lines) - row].string = res

    def on_emulator_memory_range_mapped(self, data):
        address, size = data
        _address = QStandardItem()
        str_frmt = ''
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

    def on_emulator_start(self):
        pass

    def on_emulator_stop(self):
        self.app.context_panel.set_context(0, 2, self.emulator.current_context)
        # check if the previous hook is waiting for a register result
        if self._require_register_result is not None:
            row = 1
            res = '%s = %s' % (self._require_register_result[1],
                               hex(self.emulator.uc.reg_read(self._require_register_result[0])))
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
