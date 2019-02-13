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
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QListWidgetItem, QTableWidgetItem


class NotEditableListWidgetItem(QListWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)
        self.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

        self.data = None

    def set_data(self, data):
        self.data = data

    def get_data(self):
        return self.data


class NotEditableTableWidgetItem(QTableWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)
        self.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

        self.data = None

    def set_data(self, data):
        self.data = data

    def get_data(self):
        return self.data
