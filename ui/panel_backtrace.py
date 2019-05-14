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
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QHeaderView, QMenu

from ui.list_view import DwarfListView


class BacktracePanel(DwarfListView):

    onShowMemoryRequest = pyqtSignal(str, name='onShowMemoryRequest')

    def __init__(self, parent=None):
        super(BacktracePanel, self).__init__(parent=parent)
        self._app_window = parent

        self._model = QStandardItemModel(0, 2)
        self._model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._model.setHeaderData(1, Qt.Horizontal, 'Symbol')

        self.setModel(self._model)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.doubleClicked.connect(self._item_doubleclicked)
        self._mode = 'native'

    def set_backtrace(self, bt):
        if 'type' not in bt:
            return

        self.clear()

        if bt['type'] == 'native':
            self._mode = 'native'
            self._model.setHeaderData(0, Qt.Horizontal, 'Address')
            self._model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
            self._model.setHeaderData(1, Qt.Horizontal, 'Symbol')

            bt = bt['bt']

            for a in bt:
                addr = a['address']
                if self.uppercase_hex:
                    addr = addr.upper().replace('0X', '0x')

                addr_item = QStandardItem()
                addr_item.setText(addr)
                addr_item.setTextAlignment(Qt.AlignCenter)

                name = a['name']
                if name is None:
                    name = '-'

                self._model.appendRow([addr_item, QStandardItem(name)])

        elif bt['type'] == 'java':
            self._mode = 'java'
            self.clear()
            self._model.setHeaderData(0, Qt.Horizontal, 'Method')
            self._model.setHeaderData(0, Qt.Horizontal, Qt.AlignLeft, Qt.TextAlignmentRole)
            self._model.setHeaderData(1, Qt.Horizontal, 'Source')

            bt = bt['bt']
            parts = bt.split('\n')
            for i in range(0, len(parts)):
                if i == 0:
                    continue
                p = parts[i].replace('\t', '')
                p = p.split('(')
                if len(p) != 2:
                    continue

                self._model.appendRow([QStandardItem(p[0]), QStandardItem(p[1].replace(')', ''))])

    def _item_doubleclicked(self, model_index):
        row = self._model.itemFromIndex(model_index).row()
        if row != -1:
            if self._mode == 'native':
                self.onShowMemoryRequest.emit(self._model.item(row, 0).text())
