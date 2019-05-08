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
from PyQt5.QtWidgets import QListWidget, QDialog, QVBoxLayout, QHBoxLayout, QPushButton

from ui.list_view import DwarfListView


class ListDialog(QDialog):
    def __init__(self, parent=None, setup_list_cb=None, setup_list_cb_args=None,
                 double_click_to_accept=False, checkable=False):
        super(ListDialog, self).__init__(parent)

        self.right_click_handler = None

        layout = QVBoxLayout(self)
        self.list = DwarfListView()  # QListWidget()

        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        if double_click_to_accept:
            self.list.doubleClicked.connect(self.accept)

        if setup_list_cb is not None:
            setup_list_cb(self.list, setup_list_cb_args)

        layout.addWidget(self.list)
        if checkable:
            buttons = QHBoxLayout()
            select_all = QPushButton('select all')
            select_all.clicked.connect(self.select_all)
            buttons.addWidget(select_all)
            unselect_all = QPushButton('unselect all')
            unselect_all.clicked.connect(self.unselect_all)
            buttons.addWidget(unselect_all)
            ok = QPushButton('ok')
            ok.clicked.connect(self.accept)
            buttons.addWidget(ok)
            cancel = QPushButton('cancel')
            cancel.clicked.connect(self.close)
            buttons.addWidget(cancel)
            layout.addLayout(buttons)

    def get_checked_items(self):
        ret = []
        for i in range(0, self.list.count()):
            item = self.list.item(i)
            if item.checkState() == Qt.Checked:
                ret.append(item)
        return ret

    def select_all(self):
        for i in range(0, self.list.count()):
            item = self.list.item(i)
            item.setCheckState(Qt.Checked)

    def unselect_all(self):
        for i in range(0, self.list.count()):
            item = self.list.item(i)
            item.setCheckState(Qt.Unchecked)

    def keyPressEvent(self, event):
        super(ListDialog, self).keyPressEvent(event)
        if event.key() == Qt.Key_Return:
            self.accept()

    @staticmethod
    def build_and_show(setup_list_cb, setup_list_cb_args, double_click_to_accept=False, checkable=False):
        dialog = ListDialog(setup_list_cb=setup_list_cb, setup_list_cb_args=setup_list_cb_args,
                            double_click_to_accept=double_click_to_accept, checkable=checkable)
        if dialog.list.count() > 0:
            result = dialog.exec_()
            if checkable:
                if result == QDialog.Accepted:
                    checked_items = dialog.get_checked_items()
                else:
                    checked_items = []
                return result == QDialog.Accepted, checked_items

            return result == QDialog.Accepted, dialog.list.selectedItems()
        return None
