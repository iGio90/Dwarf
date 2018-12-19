from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QAbstractItemView, QMenu
from capstone import *
from hexdump import hexdump

from lib import utils
from ui.dialog_input import InputDialog
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

        self.verticalHeader().hide()
        self.horizontalHeader().hide()

        self.resizeColumnsToContents()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        cell = self.itemAt(pos)
        menu = QMenu()

        if isinstance(cell, ByteWidget):
            data = menu.addAction("Show as data\t(D)")
            menu.addAction(data)

            follow = menu.addAction("Follow pointer\t(F)")
            menu.addAction(follow)

            sep1 = utils.get_qmenu_separator()
            menu.addAction(sep1)

            hex_view = menu.addAction("HEX\t(H)")
            if self.view == VIEW_HEX:
                hex_view.setEnabled(False)
            menu.addAction(hex_view)

            asm_view = menu.addAction("ASM\t(A)")
            if self.view == VIEW_ASM:
                asm_view.setEnabled(False)
            menu.addAction(asm_view)

            sep2 = utils.get_qmenu_separator()
            menu.addAction(sep2)

        mode = None
        if self.app.get_arch() == 'arm' and self.view == VIEW_ASM:
            if self.cs_mode == CS_MODE_ARM:
                mode = menu.addAction("THUMB mode\t(O)")
                menu.addAction(mode)
            elif self.cs_mode == CS_MODE_THUMB:
                mode = menu.addAction("ARM mode\t(O)")
                menu.addAction(mode)

            sep3 = utils.get_qmenu_separator()
            menu.addAction(sep3)

        jump_to = menu.addAction("Jump to\t(G)")

        action = menu.exec_(self.mapToGlobal(pos))
        if action == jump_to:
            self.trigger_jump_to()
        elif isinstance(cell, ByteWidget):
            if action == follow:
                self.trigger_follow_pointer()
            elif action == hex_view:
                self.set_view_type(VIEW_HEX)
            elif action == asm_view:
                self.set_view_type(VIEW_ASM)

        if self.app.get_arch() == 'arm':
            if mode is not None and action == mode:
                self.swap_arm_mode()

    def read_pointer(self, byte_widget):
        row = byte_widget.row()
        col = byte_widget.column()
        data = []
        for i in range(0, self.app.get_pointer_size()):
            q = self.item(row, col)
            if isinstance(q, ByteWidget):
                data.append(q.get_value())
                col += 1
            else:
                row += 1
                col = 1
        return int.from_bytes(bytes(data), 'little')

    def _set_data(self, start, data, jump_to=-1):
        if start % 2 == 1:
            start -= 1
        l = len(data)
        self.data = {
            'start': start,
            'end': start + l,
            'len': l,
            'data': data,
            'jt': jump_to
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
        self.asm_data_start = (c_item.row() * 16) + col
        self.asm_parse_start = self.data['start'] + self.asm_data_start

        if self.asm_parse_start + 32 > self.data['end']:
            self.read_memory(self.asm_parse_start, 32, 0)
        else:
            self.view = VIEW_ASM
            self.horizontalHeader().hide()
            self.setColumnCount(3)

            self._finalize_asm_view()

    def _finalize_asm_view(self):
        self.setRowCount(0)

        if self.app.get_arch() == 'arm64':
            arch = CS_ARCH_ARM64
            self.cs_mode = CS_MODE_ARM
        else:
            arch = CS_ARCH_ARM

        md = Cs(arch, self.cs_mode)
        s_row = -1

        for i in md.disasm(self.data['data'][self.asm_data_start:self.asm_data_start+64], self.asm_parse_start):
            row = self.rowCount()
            self.insertRow(row)
            if i.address == self.asm_parse_start:
                s_row = row

            w = NotEditableTableWidgetItem('0x%x' % i.address)
            w.setForeground(Qt.red)
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
            w = NotEditableTableWidgetItem(hex(offset))
            w.setForeground(Qt.red)
            self.setItem(row, 0, w)

            rr = rr[1].split('  ')
            hex_line = rr[0][1:] + ' ' + rr[1]
            hex_line = hex_line.split(' ')

            for i in range(0, len(hex_line)):
                qq = ByteWidget(hex_line[i])
                qq.set_value(int(hex_line[i], 16))

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

    def read_memory(self, ptr, size=1024, sub_start=512):
        try:
            range = self.app.script.exports.getrange(ptr)
        except:
            return

        if len(range) == 0:
            return

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
        data = self.app.script.exports.memread(start, size)
        if len(data) == 0:
            return
        self.view = VIEW_NONE
        self._set_data(start, data, jump_to=offset)
        self.set_view_type(VIEW_HEX)

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

    def trigger_jump_to(self):
        pt = InputDialog.input(hint='insert pointer', size=True)
        if pt[0]:
            ptr = self.app.get_script().exports.getpt(pt[1])
            self.read_memory(ptr, int(pt[2]), sub_start=int(pt[3]))

    def trigger_follow_pointer(self):
        if len(self.selectedItems()) > 0 and isinstance(self.selectedItems()[0], ByteWidget):
            self.read_memory(self.read_pointer(self.selectedItems()[0]))

    def set_view_type(self, view_type):
        if self.view == view_type or self.data is None:
            return
        if view_type == VIEW_HEX:
            self._set_memory_view()
        elif view_type == VIEW_ASM:
            self._set_asm_view()
