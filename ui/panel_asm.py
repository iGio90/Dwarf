"""
Dwarf - Copyright (C) 2018 iGio90

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
from keystone import *

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu, QAction

from lib import utils
from ui.dialog_write_instruction import WriteInstructionDialog
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget


class AsmPanel(QTableWidget):
    def __init__(self, app):
        super(AsmPanel, self).__init__(app)

        self.setStyleSheet("background-image: url('%s'); background-repeat: no-repeat; "
                           "background-attachment: fixed; background-position: center;" %
                           utils.resource_path('ui/dwarf_alpha.png'))

        self.app = app
        self.range = None
        self.offset = 0

        self.cs_arch = 0
        self.cs_mode = 0
        self.ks_arch = 0
        self.ks_mode = 0

        self.on_arch_changed()

        self.horizontalHeader().hide()
        self.verticalHeader().hide()
        self.setColumnCount(4)
        self.setShowGrid(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        menu = QMenu()

        if self.cs_arch == CS_ARCH_ARM:
            if self.cs_mode == CS_MODE_ARM:
                mode = QAction("THUMB mode\t(O)")
            else:
                mode = QAction("ARM mode\t(O)")
            mode.triggered.connect(self.swap_arm_mode)
            menu.addAction(mode)

            sep3 = utils.get_qmenu_separator()
            menu.addAction(sep3)

        write_instr_action = menu.addAction("Patch instruction")
        write_instr_action.triggered.connect(self.trigger_write_instruction)
        menu.exec_(self.mapToGlobal(pos))

    def disasm(self, range, offset):
        self.setRowCount(0)

        self.range = range
        self.offset = offset

        md = Cs(self.cs_arch, self.cs_mode)

        insts = 0
        for i in md.disasm(self.range.data[self.offset:], self.range.base + self.offset):
            if insts > 1024:
                break
            row = self.rowCount()
            self.insertRow(row)

            w = MemoryAddressWidget('0x%x' % i.address)
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.red)
            w.set_address(i.address)
            w.set_offset(self.range.base - i.address)
            self.setItem(row, 0, w)

            w = NotEditableTableWidgetItem(binascii.hexlify(i.bytes).decode('utf8'))
            w.setFlags(Qt.NoItemFlags)
            w.setForeground(Qt.darkYellow)
            self.setItem(row, 1, w)

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
        if not self.isVisible():
            self.showMaximized()

    def swap_arm_mode(self):
        if self.app.get_arch() == 'arm':
            if self.cs_mode == CS_MODE_ARM:
                self.cs_mode = CS_MODE_THUMB
            elif self.cs_mode == CS_MODE_THUMB:
                self.cs_mode = CS_ARCH_ARM
            self.disasm()

    def trigger_write_instruction(self):
        if len(self.selectedItems()) == 0:
            return
        item = self.selectedItems()[0]

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
                if self.app.dwarf_api('writeBytes', [asm_widget.get_address(), encoding]):
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
                self.app.get_log_panel().log(str(e))

    def on_arch_changed(self):
        if self.app.get_arch() == 'arm64':
            self.cs_arch = CS_ARCH_ARM64
            self.cs_mode = CS_MODE_LITTLE_ENDIAN
            self.ks_arch = KS_ARCH_ARM64
            self.ks_mode = KS_MODE_LITTLE_ENDIAN
        else:
            self.cs_arch = CS_ARCH_ARM
            self.cs_mode = CS_MODE_ARM
            self.ks_arch = KS_ARCH_ARM
            self.ks_mode = KS_MODE_ARM
