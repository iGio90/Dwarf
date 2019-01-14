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
from PyQt5.QtWidgets import *

from ui.widget_item_not_editable import NotEditableListWidgetItem


class DataPanel(QSplitter):
    def __init__(self, app):
        super(DataPanel, self).__init__(app)

        self.app = app
        self.data = {}

        self.setOrientation(Qt.Horizontal)
        self.setHandleWidth(1)

        self.key_lists = QListWidget()
        self.key_lists.itemDoubleClicked.connect(self.list_item_double_clicked)
        self.addWidget(self.key_lists)

        self.editor = QPlainTextEdit()
        self.addWidget(self.editor)

        self.setStretchFactor(0, 2)
        self.setStretchFactor(1, 4)

    def clear(self):
        self.key_lists.clear()
        self.editor.setPlainText('')

    def append_data(self, key, text_data):
        if key not in self.data:
            self.key_lists.addItem(NotEditableListWidgetItem(key))
        self.data[key] = text_data

    def list_item_double_clicked(self, item):
        self.editor.setPlainText(self.data[item.text()])
