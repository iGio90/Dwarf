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
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QListWidget, QDialog, QVBoxLayout


class ListDialog(QDialog):
    def __init__(self, parent=None, setup_list_cb=None, setup_list_cb_args=None,
                 double_click_to_accept=False):
        super(ListDialog, self).__init__(parent)

        self.right_click_handler = None

        layout = QVBoxLayout(self)
        self.list = QListWidget()

        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        if double_click_to_accept:
            self.list.itemDoubleClicked.connect(self.accept)

        if setup_list_cb is not None:
            setup_list_cb(self.list, setup_list_cb_args)

        layout.addWidget(self.list)

    def keyPressEvent(self, event):
        super(ListDialog, self).keyPressEvent(event)
        if event.key() == Qt.Key_Return:
            self.accept()

    @staticmethod
    def build_and_show(setup_list_cb, setup_list_cb_args, double_click_to_accept=False):
        dialog = ListDialog(setup_list_cb=setup_list_cb, setup_list_cb_args=setup_list_cb_args,
                            double_click_to_accept=double_click_to_accept)
        if dialog.list.count() > 0:
            result = dialog.exec_()
            return result == QDialog.Accepted, dialog.list.selectedItems()
        return None
