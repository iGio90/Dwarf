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
import pyperclip
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu, QAbstractItemView, QAction

from lib import utils
from ui.dialog_input import InputDialog
from ui.widget_memory_address import MemoryAddressWidget


class TableBaseWidget(QTableWidget):
    def __init__(self, parent, *__args):
        super().__init__(*__args)
        self.app = parent

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.itemDoubleClicked.connect(self._item_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.current_search = ''

    def _show_menu(self, pos):
        item = self.itemAt(pos)
        menu = QMenu()
        search = None
        if isinstance(item, MemoryAddressWidget):
            sym = self.app.dwarf.dwarf_api('getSymbolByAddress', item.get_address())
            if sym is not None:
                if sym['name'] == '' or sym['name'] is None:
                    sym['name'] = sym['address']
                sym_action = menu.addAction('%s (%s)' % (sym['name'], sym['moduleName']))
                sym_action.setEnabled(False)
                menu.addSeparator()
        else:
            if self.is_search_enabled():
                search = menu.addAction('Search')
                menu.addSeparator()

        self.set_menu_actions(item, menu)

        copy_address = None
        if isinstance(item, MemoryAddressWidget):
            if len(menu.actions()) > 0:
                menu.addSeparator()

            if self.app.dwarf.dwarf_api('isAddressWatched', item.get_address()):
                watcher = menu.addAction('Remove memory watcher')
            else:
                watcher = menu.addAction('Add memory watcher')
            jump_to_address = menu.addAction('Jump to pointer')
            dump = menu.addAction('Dump binary')
            menu.addSeparator()
            copy_address = menu.addAction('Copy address')

        action = menu.exec_(self.mapToGlobal(pos))
        if action:
            if search is not None and action == search:
                self.search()
            if not self.on_menu_action(action.data(), item):
                return
            if isinstance(item, MemoryAddressWidget):
                if action == copy_address:
                    pyperclip.copy(hex(item.get_address()))
                elif action == watcher:
                    if self.app.dwarf.dwarf_api('isAddressWatched', item.get_address()):
                        self.app.dwarf.remove_watcher(item.get_address())
                    else:
                        self.app.dwarf.add_watcher(item.get_address())
                elif action == jump_to_address:
                    self.app.memory_panal.read_memory(ptr=item.get_address(),
                                                            length=item.get_size(),
                                                            base=item.get_base_address())
                elif action == dump:
                    self.app.dwarf.dump_memory(ptr=item.get_address(), length=item.get_size())

    def _item_double_clicked(self, item):
        if not item:
            return

        if not self.item_double_clicked(item):
            return

        if isinstance(item, MemoryAddressWidget):
            self.app.memory_panel.read_memory(ptr=item.get_address(),
                                                    length=item.get_size(),
                                                    base=item.get_base_address())

    def keyPressEvent(self, event):
        if event.modifiers() & Qt.ControlModifier:
            if event.key() == Qt.Key_F:
                self.search()
        super(TableBaseWidget, self).keyPressEvent(event)

    def is_search_enabled(self):
        return True

    def item_double_clicked(self, item):
        return True

    def on_menu_action(self, action_data, item):
        return True

    def search(self):
        accept, input = InputDialog.input(self.app, hint='Search',
                                          input_content=self.current_search,
                                          placeholder='Search something...')
        if accept:
            self.current_search = input.lower()
            for i in range(0, self.rowCount()):
                match = False
                for c in range(0, self.columnCount()):
                    item = self.item(i, c)
                    try:
                        if str(item.text().lower()).index(self.current_search) >= 0:
                            match = True
                            break
                    except:
                        pass
                self.setRowHidden(i, not match)

    def set_menu_actions(self, item, menu):
        pass
