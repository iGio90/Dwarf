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

from PyQt5.QtGui import QFont
from capstone import *

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu, QAction

from lib import utils
from lib.range import Range
from ui.dialog_cs_configs import CsConfigsDialog
from ui.dialog_input import InputDialog
from ui.dialog_write_instruction import WriteInstructionDialog
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget


class AsmPanel(QTableWidget):
    def __init__(self, app):
        super(AsmPanel, self).__init__(app)

        self.app = app
        self.dwarf = app.get_dwarf()
        self.range = None

        self.cs_arch = 0
        self.cs_mode = 0
        self.ks_arch = 0
        self.ks_mode = 0

        self.on_arch_changed()

        self.horizontalHeader().hide()
        self.verticalHeader().hide()
        self.setColumnCount(5)
        self.setShowGrid(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)
        self.itemDoubleClicked.connect(self.item_double_clicked)

        self.history = []

    def show_menu(self, pos):
        menu = QMenu()

        cs_config = menu.addAction("Capstone")

        if self.cs_arch == CS_ARCH_ARM:
            if self.cs_mode == CS_MODE_ARM:
                mode = QAction("THUMB mode\t(O)")
            else:
                mode = QAction("ARM mode\t(O)")
            mode.triggered.connect(self.swap_arm_mode)
            menu.addAction(mode)

            menu.addSeparator()

        write_instr = menu.addAction("Patch instruction")

        menu.addSeparator()

        jump_to = menu.addAction("Jump to\t(G)")
        jump_to.triggered.connect(self.trigger_jump_to)

        action = menu.exec_(self.mapToGlobal(pos))
        if action == cs_config:
            self.trigger_cs_configs()
        elif action == write_instr:
            self.trigger_write_instruction(self.itemAt(pos))

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_G:
            self.trigger_jump_to()
        elif event.key() == Qt.Key_O:
            self.swap_arm_mode()
        elif event.key() == Qt.Key_Escape:
            if len(self.history) > 1:
                self.history.pop(len(self.history) - 1)
                self.read_memory(self.history[len(self.history) - 1])
        else:
            # dispatch those to super
            super(AsmPanel, self).keyPressEvent(event)

    def trigger_jump_to(self):
        ptr, input = InputDialog.input_pointer(self.app)
        if ptr > 0:
            self.read_memory(ptr)

    def item_double_clicked(self, item):
        if isinstance(item, MemoryAddressWidget):
            self.read_memory(item.get_address())

    def read_memory(self, ptr, length=0):
        if self.range is None:
            self.range = Range(Range.SOURCE_TARGET, self.dwarf)
        init = self.range.init_with_address(ptr, length)
        if init > 0:
            return 1
        self.disasm()
        return 0

    def disasm(self, _range=None):
        self.setRowCount(0)

        if _range:
            self.range = _range

        if self.range is None:
            return 1

        if len(self.history) == 0 or self.history[len(self.history) - 1] != self.range.start_address:
            self.history.append(self.range.start_address)
            if len(self.history) > 25:
                self.history.pop(0)

        md = Cs(self.cs_arch, self.cs_mode)
        md.detail = True

        insts = 0
        for i in md.disasm(self.range.data[self.range.start_offset:], self.range.start_address):
            if insts > 128:
                break

            row = self.rowCount()
            self.insertRow(row)

            w = MemoryAddressWidget('0x%x' % i.address)
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.red)
            w.set_offset(self.range.base - i.address)
            self.setItem(row, 0, w)

            w = NotEditableTableWidgetItem(binascii.hexlify(i.bytes).decode('utf8'))
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.darkYellow)
            self.setItem(row, 1, w)

            is_jmp = False
            if CS_GRP_JUMP in i.groups or CS_GRP_CALL in i.groups:
                is_jmp = True

            op_imm_value = 0
            if len(i.operands) > 0:
                for op in i.operands:
                    if op.type == CS_OP_IMM:
                        if len(i.operands) == 1:
                            is_jmp = True
                        if is_jmp:
                            op_imm_value = op.value.imm
                            sym = self.app.dwarf_api('getSymbolByAddress', op_imm_value)
                            module = ''
                            if 'moduleName' in sym:
                                module = '- %s' % sym['moduleName']
                            w = NotEditableTableWidgetItem('%s %s' % (sym['name'], module))
                            w.setFlags(Qt.NoItemFlags)
                            w.setForeground(Qt.lightGray)
                            self.setItem(row, 4, w)

            if is_jmp and op_imm_value > 0:
                w = MemoryAddressWidget(i.op_str)
                w.set_address(op_imm_value)
            else:
                w = NotEditableTableWidgetItem(i.op_str)
                w.setFlags(Qt.NoItemFlags)
                w.setForeground(Qt.lightGray)
            self.setItem(row, 3, w)

            w = NotEditableTableWidgetItem(i.mnemonic.upper())
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.white)
            w.setTextAlignment(Qt.AlignCenter)
            w.setFont(QFont(None, 11, QFont.Bold))
            self.setItem(row, 2, w)

            insts += 1

        self.resizeColumnsToContents()
        self.scrollToTop()
        return 0

    def clear(self):
        self.range = None

    def swap_arm_mode(self):
        if self.dwarf.arch == 'arm':
            if self.cs_mode == CS_MODE_ARM:
                self.cs_mode = CS_MODE_THUMB
            elif self.cs_mode == CS_MODE_THUMB:
                self.cs_mode = CS_ARCH_ARM
            self.disasm()

    def trigger_cs_configs(self):
        accept, arch, mode = CsConfigsDialog.show_dialog(self.cs_arch, self.cs_mode)
        if accept:
            self.cs_arch = arch
            self.cs_mode = mode
            self.disasm()

    def trigger_write_instruction(self, item):
        if not self.dwarf.keystone_installed:
            details = ''
            try:
                import keystone.keystone_const
            except Exception as e:
                details = str(e)
            utils.show_message_box(
                'keystone-engine not found. Install it to enable instructions patching',
                details=details)
            return

        accept, inst, arch, mode = WriteInstructionDialog().show_dialog(
            input_content='%s %s' % (self.item(item.row(), 1).text(), self.item(item.row(), 2).text()),
            arch=self.ks_arch,
            mode=self.ks_mode
        )

        self.ks_arch = 'KS_ARCH_' + arch.upper()
        self.ks_mode = 'KS_MODE_' + mode.upper()

        if accept and len(inst) > 0:
            import keystone
            try:
                ks = keystone.Ks(getattr(keystone.keystone_const, self.ks_arch),
                                 getattr(keystone.keystone_const, self.ks_mode))
                encoding, count = ks.asm(inst)
                asm_widget = self.item(item.row(), 0)
                offset = asm_widget.get_offset()
                if self.dwarf.dwarf_api('writeBytes', [asm_widget.get_address(), encoding]):
                    new_data = bytearray(self.range.data)
                    for i in range(0, len(encoding)):
                        try:
                            new_data[self.asm_data_start + offset + i] = encoding[i]
                        except Exception as e:
                            if isinstance(e, IndexError):
                                break
                    self.range.data = bytes(new_data)
                    self.disa()
            except Exception as e:
                self.dwarf.log(e)

    def on_arch_changed(self):
        if self.dwarf.arch == 'arm64':
            self.cs_arch = CS_ARCH_ARM64
            self.cs_mode = CS_MODE_LITTLE_ENDIAN
        else:
            self.cs_arch = CS_ARCH_ARM
            self.cs_mode = CS_MODE_ARM
        if self.dwarf.keystone_installed:
            import keystone.keystone_const as ks
            if self.dwarf.arch == 'arm64':
                self.ks_arch = ks.KS_ARCH_ARM64
                self.ks_mode = ks.KS_MODE_LITTLE_ENDIAN
            else:
                self.ks_arch = ks.KS_ARCH_ARM
                self.ks_mode = ks.KS_MODE_ARM
