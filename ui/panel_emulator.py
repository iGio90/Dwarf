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

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QSplitter, QTableWidget, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget, \
    QTabWidget, QHeaderView

from lib.range import Range
from ui.dialog_emulator_configs import EmulatorConfigsDialog
from ui.dialog_input import InputDialog
from ui.widget_console import QConsoleWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem, NotEditableListWidgetItem
from ui.widget_memory import QMemoryWidget
from ui.widget_memory_address import MemoryAddressWidget

from capstone import *
from unicorn.unicorn_const import UC_MEM_READ


class AsmTableWidget(QTableWidget):
    def __init__(self, app):
        super().__init__(0, 5)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalHeader().hide()
        self.setShowGrid(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)
        self.model().rowsInserted.connect(self.on_row_inserted)

        self._require_register_result = None
        self._last_instruction_address = 0

    def add_hook(self, emulator, instruction):
        # check if the previous hook is waiting for a register result
        if self._require_register_result is not None:
            res = '%s = %s' % (self._require_register_result[1],
                               hex(emulator.uc.reg_read(self._require_register_result[0])))
            self.setItem(self.rowCount() - 1, 4, NotEditableTableWidgetItem(res))
            # invalidate
            self._require_register_result = None

        # check if the code jumped
        if self._last_instruction_address > 0:
            if instruction.address > self._last_instruction_address + self.app.get_dwarf().pointer_size or\
                    instruction.address < self._last_instruction_address:
                # insert an empty line
                self.insertRow(self.rowCount())
        self._last_instruction_address = instruction.address

        row = self.rowCount()
        self.insertRow(row)

        address = instruction.address
        if instruction.thumb:
            address = address | 1
        w = MemoryAddressWidget('0x%x' % address)
        w.setFlags(Qt.NoItemFlags)
        w.setForeground(Qt.red)
        self.setItem(row, 0, w)

        w = NotEditableTableWidgetItem(binascii.hexlify(instruction.bytes).decode('utf8'))
        w.setFlags(Qt.NoItemFlags)
        w.setForeground(Qt.darkYellow)
        self.setItem(row, 1, w)

        if instruction.is_jump and instruction.jump_address != 0:
            w = MemoryAddressWidget(instruction.op_str)
            w.set_address(instruction.jump_address)
        else:
            w = NotEditableTableWidgetItem(instruction.op_str)
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.lightGray)
        self.setItem(row, 3, w)

        w = NotEditableTableWidgetItem(instruction.mnemonic.upper())
        w.setFlags(Qt.NoItemFlags)
        w.setForeground(Qt.white)
        w.setTextAlignment(Qt.AlignCenter)
        w.setFont(QFont(None, 11, QFont.Bold))
        self.setItem(row, 2, w)

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

        if instruction.symbol_name is not None:
            w = NotEditableTableWidgetItem('%s (%s)' % (instruction.symbol_name, instruction.symbol_module))
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.lightGray)
            self.setItem(row, 4, w)

        self.scrollToBottom()

    def add_memory_hook(self, uc, access, address, value):
        res = None
        if access == UC_MEM_READ:
            if self._require_register_result is not None:
                res = '%s = %s' % (self._require_register_result[1], hex(value))
        else:
            if self.item(self.rowCount() - 1, 4) is not None:
                res = '%s, %s = %s' % (self.item(self.rowCount() - 1, 4).text(), hex(address), hex(value))
            else:
                res = '%s = %s' % (hex(address), hex(value))
        if res is not None:
            # invalidate
            self._require_register_result = None

            self.setItem(self.rowCount() - 1, 4, NotEditableTableWidgetItem(res))

    def on_row_inserted(self, qindex, a, b):
        self.scrollToBottom()


class MemoryTableWidget(QMemoryWidget):
    def __init__(self, app, *__args):
        super().__init__(app, *__args)

    def get_source_type(self):
        return Range.SOURCE_EMULATOR


class EmulatorPanel(QWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app
        self.emulator = self.app.get_dwarf().get_emulator()
        self.until_address = 0

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        buttons = QHBoxLayout()
        self.btn_start = QPushButton('start')
        self.btn_start.clicked.connect(self.handle_start)
        self.btn_step = QPushButton('step')
        self.btn_step.clicked.connect(self.handle_step)
        self.btn_stop = QPushButton('stop')
        self.btn_stop.clicked.connect(self.handle_stop)
        self.btn_stop.setEnabled(False)
        self.btn_clean = QPushButton('clean')
        self.btn_clean.clicked.connect(self.handle_clean)
        self.btn_clean.setEnabled(False)
        self.btn_options = QPushButton('options')
        self.btn_options.clicked.connect(self.handle_options)
        buttons.addWidget(self.btn_start)
        buttons.addWidget(self.btn_step)
        buttons.addWidget(self.btn_stop)
        buttons.addWidget(self.btn_clean)
        buttons.addWidget(self.btn_options)
        layout.addLayout(buttons)

        splitter = QSplitter()
        splitter.setHandleWidth(1)
        splitter.setOrientation(Qt.Vertical)

        self.panel = QSplitter()
        self.panel.setHandleWidth(1)
        self.panel.setOrientation(Qt.Horizontal)

        self.central_panel = QSplitter()
        self.central_panel.setHandleWidth(1)
        self.central_panel.setOrientation(Qt.Vertical)

        self.asm_table = AsmTableWidget(self.app)
        self.memory_table = MemoryTableWidget(self.app)

        self.ranges_list = QListWidget(self.app)
        self.ranges_list.itemDoubleClicked.connect(self.ranges_item_double_clicked)

        from ui.panel_context import ContextPanel
        self.context_panel = ContextPanel(self.app)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.asm_table, 'asm')
        self.tabs.addTab(self.memory_table, 'hex')

        self.central_panel.addWidget(self.context_panel)
        self.central_panel.addWidget(self.tabs)

        self.central_panel.setStretchFactor(0, 1)
        self.central_panel.setStretchFactor(1, 3)

        self.panel.addWidget(self.ranges_list)
        self.panel.addWidget(self.central_panel)

        self.panel.setStretchFactor(0, 1)
        self.panel.setStretchFactor(1, 4)
        splitter.addWidget(self.panel)

        self.console = QConsoleWidget(self.app)
        splitter.addWidget(self.console)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)
        self.setLayout(layout)

        self.app.get_dwarf().get_bus().add_event(self.on_emulator_start, 'emulator_start')
        self.app.get_dwarf().get_bus().add_event(self.on_emulator_stop, 'emulator_stop')
        self.app.get_dwarf().get_bus().add_event(self.on_emulator_hook, 'emulator_hook')
        self.app.get_dwarf().get_bus().add_event(self.on_emulator_memory_hook, 'emulator_memory_hook')
        self.app.get_dwarf().get_bus().add_event(self.on_emulator_memory_range_mapped, 'emulator_memory_range_mapped')
        self.app.get_dwarf().get_bus().add_event(self.on_emulator_log, 'emulator_log')

    def handle_clean(self):
        self.ranges_list.clear()
        self.asm_table.setRowCount(0)
        self.memory_table.setRowCount(0)
        self.console.clear()
        self.emulator.clean()

    def handle_options(self):
        EmulatorConfigsDialog.show_dialog(self.app.get_dwarf())

    def handle_start(self):
        ph = ''
        if self.until_address > 0:
            ph = hex(self.until_address)
        address, inp = InputDialog.input_pointer(self.app, input_content=ph,
                                                 hint='pointer to last instruction')
        if address > 0:
            self.until_address = address
            err = self.emulator.start(self.until_address)
            if err > 0:
                self.until_address = 0
                self.console.log('cannot start emulator. err: %d' % err)
                return

    def handle_step(self):
        err = self.emulator.start()
        if err > 0:
            self.until_address = 0
            self.console.log('cannot start emulator. err: %d' % err)
            return

    def handle_stop(self):
        self.emulator.stop()

    def on_emulator_hook(self, emulator, instruction):
        self.context_panel.set_context(emulator.current_context.pc, 2, emulator.current_context)
        self.asm_table.add_hook(emulator, instruction)

    def on_emulator_log(self, log):
        self.console.log(log)

    def on_emulator_memory_hook(self, uc, access, address, value):
        self.asm_table.add_memory_hook(uc, access, address, value)

    def on_emulator_memory_range_mapped(self, address, size):
        q = NotEditableListWidgetItem(hex(address))
        q.setForeground(Qt.red)
        self.ranges_list.addItem(q)
        self.ranges_list.sortItems()

    def on_emulator_start(self):
        self.btn_start.setEnabled(False)
        self.btn_step.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_clean.setEnabled(False)
        self.btn_options.setEnabled(False)

    def on_emulator_stop(self):
        self.btn_start.setEnabled(True)
        self.btn_step.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_clean.setEnabled(True)
        self.btn_options.setEnabled(True)

    def ranges_item_double_clicked(self, item):
        self.memory_table.read_memory(item.text())
        self.tabs.setCurrentWidget(self.memory_table)
