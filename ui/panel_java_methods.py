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

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_table_base import TableBaseWidget


class JavaMethodsPanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 1)
        self.app = app
        self.java_class = ''
        self.horizontalHeader().hide()
        self.horizontalHeader().setStretchLastSection(True)

    def set_menu_actions(self, item, menu):
        if item is not None:
            menu.addSeparator()
            action_hook = menu.addAction('Hook')
            action_hook.setData('hook')

    def on_menu_action(self, action_data, item):
        if action_data == 'hook':
            self.app.get_dwarf().hook_java(self.java_class + '.' + item.text())

        return True

    def initialize_with_class(self, java_class):
        self.java_class = java_class
        self.app.get_dwarf().get_bus().add_event(self.on_enumeration_complete, java_class)
        self.app.dwarf_api('enumerateJavaMethods', java_class)

    def on_enumeration_complete(self, methods, class_name):
        for method in sorted(methods):
            row = self.rowCount()
            self.insertRow(row)
            q = NotEditableTableWidgetItem(method)
            q.setFlags(Qt.ItemIsEnabled)
            self.setItem(row, 0, q)
