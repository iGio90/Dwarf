"""
Dwarf - Copyright (C) 2019 iGio90

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
import pyperclip
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu, QAbstractItemView

from ui.widget_memory_address import MemoryAddressWidget


class TableBaseWidget(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.itemDoubleClicked.connect(self._item_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

    def _show_menu(self, pos):
        item = self.itemAt(pos)
        menu = QMenu()
        self.set_menu_actions(item, menu)

        copy_address = None
        if isinstance(item, MemoryAddressWidget):
            if len(menu.actions()) > 0:
                menu.addSeparator()
            jump_to_address = menu.addAction('Jump to pointer')
            dump = menu.addAction('Dump binary')
            menu.addSeparator()
            copy_address = menu.addAction('Copy address')

        action = menu.exec_(self.mapToGlobal(pos))
        if action:
            if not self.on_menu_action(action.data(), item):
               return
            if isinstance(item, MemoryAddressWidget):
                if action == copy_address:
                    pyperclip.copy(hex(item.get_address()))
                elif action == jump_to_address:
                    self.app.get_memory_panel().read_memory(ptr=item.get_address(),
                                                            length=item.get_size(),
                                                            base=item.get_base_address())
                elif action == dump:
                    self.app.get_dwarf().dump_memory(ptr=item.get_address(), length=item.get_size())

    def _item_double_clicked(self, item):
        if not item:
            return

        if not self.item_double_clicked(item):
            return

        if isinstance(item, MemoryAddressWidget):
            self.app.get_memory_panel().read_memory(ptr=item.get_address(),
                                                    length=item.get_size(),
                                                    base=item.get_base_address())

    def item_double_clicked(self, item):
        return True

    def on_menu_action(self, action_data, item):
        return True

    def set_menu_actions(self, item, menu):
        return []
