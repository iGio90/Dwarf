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
from PyQt5.QtWidgets import *


class TableDialog(QDialog):
    def __init__(self, parent=None, setup_table_cb=None, setup_table_cb_args=None):
        super(TableDialog, self).__init__(parent)

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 0)

        self.table.verticalHeader().hide()
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        if setup_table_cb is not None:
            setup_table_cb(self.table, setup_table_cb_args)

        layout.addWidget(self.table)

    def keyPressEvent(self, event):
        super(TableDialog, self).keyPressEvent(event)
        if event.key() == Qt.Key_Return:
            self.accept()

    @staticmethod
    def build_and_show(setup_table_cb, setup_table_cb_args):
        dialog = TableDialog(setup_table_cb=setup_table_cb, setup_table_cb_args=setup_table_cb_args)
        if dialog.table.rowCount() > 0:
            result = dialog.exec_()
            return result == QDialog.Accepted
        return None