"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import (QStandardItemModel, QStandardItem, QIcon,
                         QFont, QKeySequence)
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QHeaderView,
                             QPushButton, QSizePolicy, QSpacerItem, QShortcut,
                             QMenu)

from dwarf_debugger.ui.widgets.list_view import DwarfListView
from dwarf_debugger.ui.dialogs.dialog_input import InputDialog

from dwarf_debugger.lib import utils


class BookmarksWidget(QWidget):

    def __init__(self, parent=None):  # pylint: disable=too-many-statements
        super(BookmarksWidget, self).__init__(parent=parent)

        self._app_window = parent

        if self._app_window.dwarf is None:
            print('BookmarksPanel created before Dwarf exists')
            return

        self.bookmarks = {}

        self._bookmarks_list = DwarfListView()
        self._bookmarks_list.doubleClicked.connect(self._on_double_clicked)
        self._bookmarks_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._bookmarks_list.customContextMenuRequested.connect(
            self._on_contextmenu)

        self._bookmarks_model = QStandardItemModel(0, 2)
        self._bookmarks_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._bookmarks_model.setHeaderData(1, Qt.Horizontal, 'Notes')

        self._bookmarks_list.setModel(self._bookmarks_model)

        self._bookmarks_list.header().setStretchLastSection(False)
        self._bookmarks_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents | QHeaderView.Interactive)
        self._bookmarks_list.header().setSectionResizeMode(
            1, QHeaderView.Stretch | QHeaderView.Interactive)

        v_box = QVBoxLayout(self)
        v_box.setContentsMargins(0, 0, 0, 0)
        v_box.addWidget(self._bookmarks_list)
        #header = QHeaderView(Qt.Horizontal, self)

        h_box = QHBoxLayout()
        h_box.setContentsMargins(5, 2, 5, 5)
        self.btn1 = QPushButton(
            QIcon(utils.resource_path('assets/icons/plus.svg')), '')
        self.btn1.setFixedSize(20, 20)
        self.btn1.clicked.connect(lambda: self._create_bookmark(-1))
        btn2 = QPushButton(
            QIcon(utils.resource_path('assets/icons/dash.svg')), '')
        btn2.setFixedSize(20, 20)
        btn2.clicked.connect(self.delete_items)
        btn3 = QPushButton(
            QIcon(utils.resource_path('assets/icons/trashcan.svg')), '')
        btn3.setFixedSize(20, 20)
        btn3.clicked.connect(self.clear_list)
        h_box.addWidget(self.btn1)
        h_box.addWidget(btn2)
        h_box.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Preferred))
        h_box.addWidget(btn3)
        # header.setLayout(h_box)
        # header.setFixedHeight(25)
        # v_box.addWidget(header)
        v_box.addLayout(h_box)
        self.setLayout(v_box)

        self._bold_font = QFont(self._bookmarks_list.font())
        self._bold_font.setBold(True)

        shortcut_addnative = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_B), self._app_window,
            self._create_bookmark)
        shortcut_addnative.setAutoRepeat(False)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def delete_items(self):
        """ Delete selected Items
        """
        index = self._bookmarks_list.selectionModel().currentIndex().row()
        if index != -1:
            self._on_delete_bookmark(index)
            self._bookmarks_model.removeRow(index)

    def clear_list(self):
        """ Clear the List
        """
        # go through all items and tell it gets removed
        for item in range(self._bookmarks_model.rowCount()):
            self._on_delete_bookmark(item)

        if self._bookmarks_model.rowCount() > 0:
            # something was wrong it should be empty
            self._bookmarks_model.removeRows(
                0, self._bookmarks_model.rowCount())

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_double_clicked(self, index):
        index = self._bookmarks_list.selectionModel().currentIndex().row()
        if index != -1:
            addr = self._bookmarks_model.item(index, 0).text()
            if addr:
                self._app_window.jump_to_address(addr, view=1)

    def _on_contextmenu(self, pos):
        context_menu = QMenu(self)
        index = self._bookmarks_list.indexAt(pos).row()
        if index != -1:
            context_menu.addAction(
                'Copy address', lambda: utils.copy_hex_to_clipboard(
                    self._bookmarks_model.item(index, 0).text()))
            context_menu.addAction(
                'Jump to address', lambda: self._app_window.jump_to_address(
                    self._bookmarks_model.item(index, 0).text()))

            # todo: add breakpoint address menu

            context_menu.addSeparator()
            context_menu.addAction(
                'Edit', lambda: self._create_bookmark(index=index))
            context_menu.addAction(
                'Delete', lambda: self._on_delete_bookmark(index))
            context_menu.addSeparator()
            if self._bookmarks_list.search_enabled:
                context_menu.addSeparator()
                context_menu.addAction(
                    'Search', self._bookmarks_list._on_cm_search)
                context_menu.addSeparator()
        context_menu.addAction(
            'New', self._create_bookmark)
        global_pt = self._bookmarks_list.mapToGlobal(pos)
        context_menu.exec(global_pt)

    # + button
    def _create_bookmark(self, index=-1, ptr='', note=''):
        if ptr == '':
            if isinstance(index, int) and index >= 0:
                ptr = self._bookmarks_model.item(index, 0).text()
                note = self._bookmarks_model.item(index, 1).text()

            ptr, _ = InputDialog.input_pointer(
                parent=self._app_window, input_content=ptr)
        else:
            ptr = utils.parse_ptr(ptr)

        if ptr > 0:
            ptr = hex(ptr)
            if self._bookmarks_list.uppercase_hex:
                ptr = ptr.upper().replace('0X', '0x')

            index = self._bookmarks_model.findItems(ptr, Qt.MatchExactly)
            if len(index) > 0:
                index = index[0].row()
                note = self._bookmarks_model.item(index, 1).text()
            else:
                index = -1

            accept = note != ''
            if note == '':
                accept, note = InputDialog.input(
                    hint='Insert notes for %s' % ptr, input_content=note)
            if accept:
                if index < 0:
                    self.insert_bookmark(ptr, note)
                else:
                    item = self._bookmarks_model.item(index, 0)
                    item.setText(ptr)
                    item = self._bookmarks_model.item(index, 1)
                    item.setText(note)

                self.bookmarks[ptr] = note

    def insert_bookmark(self, ptr_as_hex, note):
        if self._bookmarks_list.uppercase_hex:
            ptr_as_hex = ptr_as_hex.upper().replace('0X', '0x')

        self._bookmarks_model.appendRow([
            QStandardItem(ptr_as_hex),
            QStandardItem(note)
        ])
        self._bookmarks_list.resizeColumnToContents(0)

    def is_address_bookmarked(self, ptr):
        return utils.parse_ptr(ptr) in self.bookmarks

    # shortcuts/menu
    def _on_delete_bookmark(self, index):
        ptr = self._bookmarks_model.item(index, 0).text()
        del self.bookmarks[ptr]

        self._bookmarks_model.removeRow(index)
