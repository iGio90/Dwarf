"""
Dwarf - Copyright (C) 2019 iGio90

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
import math
import time
from threading import Thread

import pyperclip
import re

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QAbstractItemView, QMenu, QAction
from hexdump import PY3K

from lib.range import Range
from ui.dialog_input import InputDialog
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_byte import ByteWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class PanelController(object):
    def __init__(self, memory_panel):
        self.memory_panel = memory_panel

        self.work = False
        self.locker = None

    def start(self, start_row):
        if self.work:
            self.work = False
            while self.locker is not None:
                time.sleep(0.1)

        self.work = True
        Thread(target=self._work, args=(start_row,)).start()

    def stop(self):
        self.work = False

    def _add_mem_address_item_if_needed(self, row):
        if not isinstance(self.memory_panel.item(row, 0), MemoryAddressWidget):
            address = self.memory_panel.range.base + (row * 16)
            q = MemoryAddressWidget(hex(address))
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.red)
            self.memory_panel.setItem(row, 0, q)

            col = 0
            offset = address - self.memory_panel.range.base
            while col < 16:
                q = ByteWidget()
                if offset + col >= self.memory_panel.range.size:
                    break
                try:
                    q.set_value(self.memory_panel.range.data[offset + col])
                except:
                    self.work = False
                    break
                q.set_ptr(address + col)
                q.set_offset(offset + col)
                self.memory_panel.setItem(row, col + 1, q)
                col += 1
            tail = offset + 16
            if tail > self.memory_panel.range.tail:
                tail = self.memory_panel.range.tail
            t = ''
            for byte in self.memory_panel.range.data[offset:tail]:
                if not PY3K:
                    byte = ord(byte)
                if 0x20 <= byte <= 0x7E:
                    t += chr(byte)
                else:
                    t += '.'
            q = NotEditableTableWidgetItem(t)
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.darkYellow)
            self.memory_panel.setItem(row, 17, q)

    def _work(self, start_row):
        if not isinstance(self.memory_panel.item(start_row, 0), MemoryAddressWidget):
            self.locker = object()
            last_back_row = start_row
            last_forw_row = start_row
            while self.work:
                if last_back_row == last_forw_row:
                    self._add_mem_address_item_if_needed(start_row)
                else:
                    if last_back_row >= 0:
                        self._add_mem_address_item_if_needed(last_back_row)
                    if last_forw_row < self.memory_panel.rowCount():
                        self._add_mem_address_item_if_needed(last_forw_row)

                if last_back_row >= 0:
                    last_back_row -= 1
                if last_forw_row < self.memory_panel.rowCount():
                    last_forw_row += 1
                if last_back_row == -1 and last_forw_row == self.memory_panel.rowCount():
                    self.work = False
                else:
                    time.sleep(0.01)
            self.locker = None


class MemoryPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(0, 18)
        self.app = app

        self.controller = PanelController(self)
        self.range = None

        self.verticalHeader().hide()
        self.horizontalHeader().hide()

        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.resizeColumnsToContents()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)
        self.setShowGrid(False)

    def show_menu(self, pos):
        cell = self.itemAt(pos)
        menu = QMenu()

        if cell:
            if isinstance(cell, ByteWidget):
                address = QAction(hex(cell.get_ptr()))
                address.triggered.connect(self.trigger_copy_address)
                menu.addAction(address)

                menu.addSeparator()

            asm_view = menu.addAction("ASM\t(A)")
            asm_view.triggered.connect(self.show_asm_view)
            menu.addAction(asm_view)

            menu.addSeparator()

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

            menu.addSeparator()

        if cell:
            wb = QAction("Write bytes")
            wb.triggered.connect(self.trigger_write_bytes)
            menu.addAction(wb)

            ws = menu.addAction("Write string")
            ws.triggered.connect(self.trigger_write_string)

            menu.addSeparator()

        jump_to = QAction("Jump to\t(G)")
        jump_to.triggered.connect(self.trigger_jump_to)
        menu.addAction(jump_to)

        menu.exec_(self.mapToGlobal(pos))

    def read_pointer(self, byte_widget):
        return self.app.dwarf_api('readPointer', byte_widget.get_ptr())

    def _set_memory_view(self, should_clear_rows=True):
        if should_clear_rows:
            self.clear()
            self.setRowCount(int(math.ceil(self.range.size / 16.0)))

        self.setColumnCount(18)
        self.horizontalHeader().show()
        h_labels = [
            ''
        ]
        for i in range(0, 16):
            h_labels.append(hex(i))
        h_labels.append('')
        self.setHorizontalHeaderLabels(h_labels)

        start_row = int(math.ceil((self.range.start_address - self.range.base) / 16.0))
        self.controller.start(start_row)

        self.setCurrentCell(start_row, 1)
        index = self.currentIndex()
        self.scrollTo(index, QAbstractItemView.PositionAtCenter)
        self.setCurrentCell(start_row, 1)
        self.horizontalHeader().setStretchLastSection(True)
        self.resizeRowsToContents()
        self.resizeColumnsToContents()

    def read_memory(self, ptr):
        if self.range is None:
            self.range = Range(self.app)

        self.app.get_session_ui().request_session_ui_focus()
        init = self.range.init_with_address(ptr)
        if init > 0:
            return 1
        self._set_memory_view(init == 0)
        return 0

    def show_asm_view(self):
        if len(self.selectedItems()) == 0:
            return

        item = self.selectedItems()[0]
        if isinstance(item, ByteWidget):
            if self.range.base < item.get_ptr() < self.range.tail:
                self.range.set_start_offset(item.get_offset())
                self.app.get_session_ui().disasm(_range=self.range)
            else:
                self.app.get_session_ui().disasm(ptr=item.get_ptr())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_G:
            self.trigger_jump_to()
        elif event.key() == Qt.Key_F:
            self.trigger_follow_pointer()
        elif event.key() == Qt.Key_A:
            self.show_asm_view()
            pass
        elif event.key() == Qt.Key_O:
            self.swap_arm_mode()
        else:
            # dispatch those to super
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
        ptr = InputDialog.input_pointer(self.app)
        if ptr > 0:
            self.read_memory(ptr)

    def trigger_write_bytes(self):
        item = self.selectedItems()[0]
        if item.column() == 0:
            item = self.item(item.row(), 1)
        if isinstance(item, ByteWidget):
            ptr = item.get_ptr()
            if ptr + 16 > self.data['end']:
                if self.read_memory(ptr) > 0:
                    return
            mem = self.app.dwarf_api('readBytes', ptr, 16)
            mem = binascii.hexlify(mem).decode('utf8')
            mem = ' '.join(re.findall('.{1,2}', mem))
            content = InputDialog.input(
                self.app,
                hint='write bytes @%s' % hex(ptr),
                input_content=mem)
            if content[0]:
                if self.app.dwarf_api('writeBytes', [ptr, content[1].replace(' ', '')]):
                    self.range.invalidate()
                    self.read_memory(ptr)

    def trigger_write_string(self):
        item = self.selectedItems()[0]
        if item.column() == 0:
            item = self.item(item.row(), 1)
        if isinstance(item, ByteWidget):
            ptr = item.get_ptr()

            accept, content = InputDialog.input(
                self.app,
                hint='write utf8 string @%s' % hex(ptr))
            if accept:
                if self.app.dwarf_api('writeUtf8', [ptr, content]):
                    self.range.invalidate()
                    self.read_memory(ptr)

    def on_script_destroyed(self):
        self.range = None
        self.controller.work = False
        self.setRowCount(0)
        self.setColumnCount(0)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)
