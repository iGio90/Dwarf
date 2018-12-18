from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QAbstractItemView, QMenu
from hexdump import hexdump

from lib import utils
from ui.dialog_input import InputDialog
from ui.widget_byte import ByteWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class MemoryPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalHeader().hide()
        h_labels = [
            ''
        ]
        for i in range(0, 16):
            h_labels.append(hex(i))
        h_labels.append('')
        self.setHorizontalHeaderLabels(h_labels)
        self.resizeColumnsToContents()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        cell = self.itemAt(pos)
        menu = QMenu()

        if isinstance(cell, ByteWidget):
            data = menu.addAction("Show as data\t(D)")
            follow = menu.addAction("Follow pointer\t(F)")

            menu.addAction(data)
            menu.addAction(follow)
            q = utils.get_qmenu_separator()
            menu.addAction(q)

        jump_to = menu.addAction("Jump to\t(G)")

        action = menu.exec_(self.mapToGlobal(pos))
        if action == jump_to:
            self.trigger_jump_to()
        elif isinstance(cell, ByteWidget):
            if action == follow:
                self.trigger_follow_pointer()

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

    def set_memory_view(self, start, data, jump_to=-1):
        self.setRowCount(0)

        s_row = -1
        s_col = 0

        for r in hexdump(data, result='return').split('\n'):
            row = self.rowCount()
            self.insertRow(row)

            rr = r.split(':')
            offset = int(rr[0], 16) + start
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
                if -1 < jump_to == offset + i:
                    qq.setSelected(True)
                    s_row = row
                    s_col = i + 1

            self.setItem(row, 17, NotEditableTableWidgetItem(rr[2]))

        if s_row > -1:
            self.setCurrentCell(s_row, 0)
            index = self.currentIndex()
            self.scrollTo(index, QAbstractItemView.PositionAtCenter)
            self.setCurrentCell(s_row, s_col)
        if self.horizontalHeader().isHidden():
            self.horizontalHeader().show()
        self.resizeColumnsToContents()

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
        self.set_memory_view(start, data, jump_to=offset)

    def keyPressEvent(self, event):
        super(MemoryPanel, self).keyPressEvent(event)
        if event.key() == Qt.Key_G:
            self.trigger_jump_to()
        elif event.key() == Qt.Key_F:
            self.trigger_follow_pointer()

    def trigger_jump_to(self):
        pt = InputDialog.input(hint='insert pointer', size=True)
        if pt[0]:
            ptr = self.app.get_script().exports.getpt(pt[1])
            self.read_memory(ptr, int(pt[2]), sub_start=int(pt[3]))

    def trigger_follow_pointer(self):
        if len(self.selectedItems()) > 0 and isinstance(self.selectedItems()[0], ByteWidget):
            self.read_memory(self.read_pointer(self.selectedItems()[0]))
