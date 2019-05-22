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
from PyQt5 import QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import *

from ui.list_view import DwarfListView
from ui.widget_item_not_editable import NotEditableListWidgetItem

from lib.range import Range
from ui.hex_edit import HexEditor


class DataPanel(QSplitter):
    def __init__(self, app):
        super(DataPanel, self).__init__(app)

        self.app = app
        self.data = {}

        self.setOrientation(Qt.Horizontal)
        self.setHandleWidth(1)

        self._key_list_model = QStandardItemModel(0, 1)
        self.key_lists = DwarfListView(parent=self.app)
        self.key_lists.setHeaderHidden(True)
        self.key_lists.setModel(self._key_list_model)
        self.key_lists.doubleClicked.connect(self.list_item_double_clicked)
        self.key_lists.setContextMenuPolicy(Qt.CustomContextMenu)
        self.key_lists.customContextMenuRequested.connect(self._on_context_menu)
        self.addWidget(self.key_lists)

        self.editor = QPlainTextEdit()
        self.addWidget(self.editor)

        self.hex_view = HexEditor(self.app)
        self.hex_view.setVisible(False)
        self.addWidget(self.hex_view)
        #self.setStretchFactor(0, 8)
        self.setStretchFactor(1, 4)

    def clear(self):
        self._key_list_model.clear()
        self.editor.setPlainText('')
        self.hex_view.clear_panel()

    def append_data(self, data_type, key, text_data):
        if key not in self.data:
            self._key_list_model.appendRow([QStandardItem(key)])
        self.data[key] = [data_type, text_data]

    def list_item_double_clicked(self, item):
        item = self._key_list_model.itemFromIndex(item)
        if self.data[item.text()][0] == 'plain':
            self.hex_view.setVisible(False)
            self.editor.setVisible(True)
            self.editor.setPlainText(self.data[item.text()][1])
        else:
            self.editor.setVisible(False)
            self.hex_view.setVisible(True)
            self.hex_view.bytes_per_line = 16
            self.hex_view.set_data(self.data[item.text()][1])

    def _on_context_menu(self, pos):
        context_menu = QMenu(self)

        index = self.key_lists.indexAt(pos).row()
        if index != -1:
            context_menu.addAction(
                'Clear', lambda: self.clear())
        global_pt = self.key_lists.mapToGlobal(pos)
        context_menu.exec(global_pt)
