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
import pyperclip
import re

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QAbstractItemView, QMenu, QAction
from capstone import *
from hexdump import hexdump

from lib import utils
from ui.dialog_input import InputDialog
from ui.dialog_write_instruction import WriteInstructionDialog
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_byte import ByteWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem

VIEW_NONE = -1
VIEW_HEX = 0
VIEW_ASM = 1


class MemoryPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(0, 18)
        self.app = app

        self.view = VIEW_NONE
        self.data = None
        self.cs_mode = CS_MODE_ARM

        self.asm_data_start = 0
        self.asm_parse_start = 0

        self.ks_arch = ''
        self.ks_mode = ''

        self.verticalHeader().hide()
        self.horizontalHeader().hide()

        self.resizeColumnsToContents()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        cell = self.itemAt(pos)
        menu = QMenu()

        if cell:
            if isinstance(cell, ByteWidget):
                address = QAction(hex(cell.get_ptr()))
                address.triggered.connect(self.trigger_copy_address)
                menu.addAction(address)

                address_sep = utils.get_qmenu_separator()
                menu.addAction(address_sep)

            hex_view = QAction("HEX\t(H)")
            if self.view == VIEW_HEX:
                hex_view.setEnabled(False)
            hex_view.triggered.connect(self.set_view_type_hex)
            menu.addAction(hex_view)

            asm_view = menu.addAction("ASM\t(A)")
            if self.view == VIEW_ASM:
                asm_view.setEnabled(False)
            asm_view.triggered.connect(self.set_view_type_asm)
            menu.addAction(asm_view)

            sep1 = utils.get_qmenu_separator()
            menu.addAction(sep1)

        if isinstance(cell, ByteWidget):
            # todo
            # data = menu.addAction("Show as data\t(D)")
            # menu.addAction(data)

            hook_address = QAction("Hook address")
            hook_address.triggered.connect(self.trigger_hook_address)
            menu.addAction(hook_address)

            follow = QAction("Follow pointer\t(F)")
            follow.triggered.connect(self.trigger_follow_pointer)
            menu.addAction(follow)

            sep2 = utils.get_qmenu_separator()
            menu.addAction(sep2)

        if self.app.get_arch() == 'arm' and self.view == VIEW_ASM:
            if self.cs_mode == CS_MODE_ARM:
                mode = QAction("THUMB mode\t(O)")
            else:
                mode = QAction("ARM mode\t(O)")
            mode.triggered.connect(self.swap_arm_mode)
            menu.addAction(mode)

            sep3 = utils.get_qmenu_separator()
            menu.addAction(sep3)

        if cell:
            if self.view == VIEW_ASM:
                write_instr_action = menu.addAction("Patch instruction")
                write_instr_action.triggered.connect(self.trigger_write_instruction)
            elif self.view == VIEW_HEX:
                wb = QAction("Write bytes")
                wb.triggered.connect(self.trigger_write_bytes)
                menu.addAction(wb)

                ws = menu.addAction("Write string")
                ws.triggered.connect(self.trigger_write_string)

            sep4 = utils.get_qmenu_separator()
            menu.addAction(sep4)

        jump_to = QAction("Jump to\t(G)")
        jump_to.triggered.connect(self.trigger_jump_to)
        menu.addAction(jump_to)

        menu.exec_(self.mapToGlobal(pos))

    def read_pointer(self, byte_widget):
        return self.app.dwarf_api('readPointer', byte_widget.get_ptr())

    def _set_data(self, start, data, sub, jump_to=-1):
        if start % 2 == 1:
            start -= 1
        l = len(data)
        self.data = {
            'start': start,
            'end': start + l,
            'len': l,
            'data': data,
            'jt': jump_to,
            'sub': sub
        }

    def _set_asm_view(self):
        if len(self.selectedItems()) < 1:
            return
        c_item = self.selectedItems()[0]
        if not isinstance(c_item, ByteWidget):
            return
        col = c_item.column()
        if col > 0:
            col -= 1
        self.asm_data_start = ((c_item.row() * 16) + col)
        self.asm_parse_start = self.data['start'] + self.asm_data_start
        self.data['jt'] = self.item(c_item.row(), 0).get_address()
        self._finalize_asm_view()

    def _finalize_asm_view(self):
        self.view = VIEW_ASM
        self.horizontalHeader().hide()
        self.setColumnCount(3)
        self.setRowCount(0)

        if self.app.get_arch() == 'arm64':
            arch = CS_ARCH_ARM64
            self.cs_mode = CS_MODE_ARM
        else:
            arch = CS_ARCH_ARM

        md = Cs(arch, self.cs_mode)
        s_row = -1

        relative_offset = 0
        for i in md.disasm(self.data['data'][self.asm_data_start:self.asm_data_start + 64], self.asm_parse_start):
            row = self.rowCount()
            self.insertRow(row)
            if i.address == self.asm_parse_start:
                s_row = row

            w = MemoryAddressWidget('0x%x' % i.address)
            w.setForeground(Qt.red)
            w.set_address(i.address)
            w.set_relative_offset(relative_offset)
            relative_offset += i.size
            self.setItem(row, 0, w)

            w = NotEditableTableWidgetItem(i.mnemonic)
            self.setItem(row, 1, w)

            w = NotEditableTableWidgetItem(i.op_str)
            self.setItem(row, 2, w)

        self.resizeColumnsToContents()

        if s_row >= 0:
            self.setCurrentCell(s_row, 0)
            index = self.currentIndex()
            self.scrollTo(index, QAbstractItemView.PositionAtCenter)
            self.setCurrentCell(s_row, 0)

    def _set_memory_view(self):
        self.view = VIEW_HEX
        self.setRowCount(0)
        self.setColumnCount(18)

        s_row = -1
        s_col = 0

        for r in hexdump(self.data['data'], result='return').split('\n'):
            row = self.rowCount()
            self.insertRow(row)

            rr = r.split(':')
            offset = int(rr[0], 16) + self.data['start']
            w = MemoryAddressWidget(hex(offset))
            w.set_address(offset)
            w.setForeground(Qt.red)
            self.setItem(row, 0, w)

            rr = rr[1].split('  ')
            hex_line = rr[0][1:] + ' ' + rr[1]
            hex_line = hex_line.split(' ')

            for i in range(0, len(hex_line)):
                qq = ByteWidget(hex_line[i])
                qq.set_value(int(hex_line[i], 16))
                qq.set_ptr(offset + i)

                self.setItem(row, i + 1, qq)
                if -1 < self.data['jt'] == offset + i:
                    qq.setSelected(True)
                    s_row = row
                    s_col = i + 1

            self.setItem(row, 17, NotEditableTableWidgetItem(rr[2]))

        if s_row > -1:
            self.setCurrentCell(s_row, 0)
            index = self.currentIndex()
            self.scrollTo(index, QAbstractItemView.PositionAtCenter)
            self.setCurrentCell(s_row, s_col)
        self.horizontalHeader().show()
        h_labels = [
            ''
        ]
        for i in range(0, 16):
            h_labels.append(hex(i))
        h_labels.append('')
        self.setHorizontalHeaderLabels(h_labels)
        self.resizeColumnsToContents()

    def swap_arm_mode(self):
        if self.app.get_arch() == 'arm':
            if self.cs_mode == CS_MODE_ARM:
                self.cs_mode = CS_MODE_THUMB
            elif self.cs_mode == CS_MODE_THUMB:
                self.cs_mode = CS_ARCH_ARM
            self._finalize_asm_view()

    def read_memory(self, ptr, size=1024, sub_start=512, view=VIEW_HEX):
        try:
            range = self.app.dwarf_api('getRange', ptr)
        except:
            return 0

        if len(range) == 0:
            return 0

        base = int(range['base'], 16)
        if isinstance(ptr, str):
            if ptr.startswith('0x'):
                offset = int(ptr, 16)
            else:
                offset = int(ptr)
        else:
            offset = ptr
        start = offset - sub_start
        end = start + size
        if start < base:
            start = base
        if end > base + range['size']:
            size = base + range['size'] - start
        data = self.app.dwarf_api('readBytes', [start, size])
        l = len(data)
        if l == 0:
            return 0
        self.view = VIEW_NONE
        self._set_data(start, data, sub_start, jump_to=offset)
        self.set_view_type(view)
        return l

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_G:
            self.trigger_jump_to()
        elif event.key() == Qt.Key_F:
            self.trigger_follow_pointer()
        elif event.key() == Qt.Key_H:
            self.set_view_type(VIEW_HEX)
        elif event.key() == Qt.Key_A:
            self.set_view_type(VIEW_ASM)
        elif event.key() == Qt.Key_O:
            self.swap_arm_mode()
        else:
            # dispatch those to super
            if event.key() == Qt.Key_Escape:
                if self.view != VIEW_HEX:
                    self.set_view_type(VIEW_HEX)
            super(MemoryPanel, self).keyPressEvent(event)

    def trigger_copy_address(self):
        item = self.selectedItems()[0]
        if item.column() == 0:
            item = self.item(item.row(), 1)
        if isinstance(item, ByteWidget):
            pyperclip.copy(hex(item.get_ptr()))

    def trigger_follow_pointer(self):
        if len(self.selectedItems()) > 0 and isinstance(self.selectedItems()[0], ByteWidget):
            self.read_memory(self.read_pointer(self.selectedItems()[0]))

    def trigger_hook_address(self):
        item = self.selectedItems()[0]
        if item.column() == 0:
            item = self.item(item.row(), 1)
        if isinstance(item, ByteWidget):
            self.app.get_hooks_panel().hook_native(hex(item.get_ptr()))

    def trigger_jump_to(self):
        pt = InputDialog.input(hint='insert pointer', size=True)
        if pt[0]:
            ptr = int(self.app.dwarf_api('evaluatePtr', pt[1]), 16)
            self.read_memory(ptr, int(pt[2]), sub_start=int(pt[3]))

    def trigger_write_bytes(self):
        item = self.selectedItems()[0]
        if item.column() == 0:
            item = self.item(item.row(), 1)
        if isinstance(item, ByteWidget):
            ptr = item.get_ptr()
            if ptr + 16 > self.data['end']:
                if self.read_memory(ptr) == 0:
                    return
            mem = self.app.dwarf_api('readBytes', ptr, 16)
            mem = binascii.hexlify(mem).decode('utf8')
            mem = ' '.join(re.findall('.{1,2}', mem))
            content = InputDialog.input(
                hint='write bytes @%s' % hex(ptr),
                input_content=mem)
            if content[0]:
                if self.app.dwarf_api('writeBytes', [ptr, content[1].replace(' ', '')]):
                    self.read_memory(ptr, self.data['len'], self.data['sub'])

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
                relative_offset = asm_widget.get_relative_offset()
                if self.app.dwarf_api('writeBytes', [asm_widget.get_address(), encoding]):
                    new_data = bytearray(self.data['data'])
                    for i in range(0, len(encoding)):
                        try:
                            new_data[self.asm_data_start + relative_offset + i] = encoding[i]
                        except Exception as e:
                            if isinstance(e, IndexError):
                                break
                    self.data['data'] = bytes(new_data)
                    self._finalize_asm_view()
            except Exception as e:
                self.app.get_log_panel().log(str(e))

    def trigger_write_string(self):
        item = self.selectedItems()[0]
        if item.column() == 0:
            item = self.item(item.row(), 1)
        if isinstance(item, ByteWidget):
            ptr = item.get_ptr()

            content = InputDialog.input(
                hint='write utf8 string @%s' % hex(ptr))
            if content[0]:
                if self.app.dwarf_api('writeUtf8', [ptr, content[1]]):
                    self.read_memory(ptr, self.data['len'], self.data['sub'])

    def set_view_type_asm(self):
        self.set_view_type(VIEW_ASM)

    def set_view_type_hex(self):
        self.set_view_type(VIEW_HEX)

    def set_view_type(self, view_type):
        if self.view == view_type or self.data is None:
            return
        if view_type == VIEW_HEX:
            self._set_memory_view()
        elif view_type == VIEW_ASM:
            self._set_asm_view()
