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
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QHeaderView, QMenu

from dwarf_debugger.ui.widgets.list_view import DwarfListView

from dwarf_debugger.lib import utils


class BacktraceWidget(DwarfListView):

    onShowMemoryRequest = pyqtSignal(list, name='onShowMemoryRequest')

    def __init__(self, parent=None):
        super(BacktraceWidget, self).__init__(parent=parent)
        self._app_window = parent

        self._app_window.dwarf.onBackTrace.connect(self.set_backtrace)

        self._model = QStandardItemModel(0, 2)
        self._model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._model.setHeaderData(1, Qt.Horizontal, 'Symbol')
        self.setModel(self._model)

        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.doubleClicked.connect(self._item_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)
        self._mode = 'native'

    def set_backtrace(self, bt):
        if 'type' not in bt:
            return

        if 'bt' not in bt:
            return

        self.clear()

        if bt['type'] == 'native':
            self._mode = 'native'
            self._model.setHeaderData(0, Qt.Horizontal, 'Address')
            self._model.setHeaderData(1, Qt.Horizontal, 'Symbol')

            bt = bt['bt']

            for a in bt:
                addr = a['address']
                if self.uppercase_hex:
                    addr = addr.upper().replace('0X', '0x')

                addr_item = QStandardItem()
                addr_item.setText(addr)
                addr_item.setForeground(Qt.red)

                name = a['name']
                if name is None:
                    name = '-'

                self._model.appendRow([addr_item, QStandardItem(name)])

        elif bt['type'] == 'java':
            self._mode = 'java'
            self._model.setHeaderData(0, Qt.Horizontal, 'Method')
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

    def _item_double_clicked(self, model_index):
        row = self._model.itemFromIndex(model_index).row()
        if row != -1:
            if self._mode == 'native':
                self.onShowMemoryRequest.emit(['bt', self._model.item(row, 0).text()])

    def _on_context_menu(self, pos):
        index = self.indexAt(pos).row()
        glbl_pt = self.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            if self._mode == 'native':
                addr_item = self.model().item(index, 0).text()
                symbol_item = self.model().item(index, 1).text()
                # show contextmenu
                context_menu.addAction('Jump to {0}'.format(addr_item), lambda: self.onShowMemoryRequest.emit(['bt', addr_item]))
                context_menu.addSeparator()
                context_menu.addAction('Copy Address', lambda: utils.copy_hex_to_clipboard(addr_item))
                if symbol_item and symbol_item != '-':
                    context_menu.addAction('Copy Symbol', lambda: utils.copy_str_to_clipboard(symbol_item))
            elif self._mode == 'java':
                method_item = self.model().item(index, 0).text()
                if method_item.startswith('at '):
                    method_item = method_item.replace('at ', '')

                source_item = self.model().item(index, 1).text()
                if ':' in source_item:
                    source_item = source_item.split(':')[0]
                # show contextmenu
                # context_menu.addAction('Jump to', lambda: self._app_window.jump_to_address(addr_item.text()))
                # context_menu.addSeparator()
                # TODO: add jumpto java
                context_menu.addAction('Copy Method', lambda: utils.copy_str_to_clipboard(method_item))
                context_menu.addAction('Copy Source', lambda: utils.copy_str_to_clipboard(source_item))

            context_menu.exec_(glbl_pt)

