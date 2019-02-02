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

from ui.panel_java_methods import JavaMethodsPanel
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_table_base import TableBaseWidget


class JavaClassesPanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 1)
        self.horizontalHeader().hide()
        self.horizontalHeader().setStretchLastSection(True)

    def set_menu_actions(self, item, menu):
        action_refresh = menu.addAction("Refresh")
        action_refresh.setData('refresh')

        if item is not None:
            menu.addSeparator()
            action_hook = menu.addAction('Hook constructor')
            action_hook.setData('hook_constructor')
            action_hook_all = menu.addAction('Hook all methods')
            action_hook_all.setData('hook_all')

    def on_menu_action(self, action_data, item):
        if action_data == 'refresh':
            self.app.app_window.get_menu().handler_enumerate_java_classes(should_update_java_classes=True)
            return False
        elif action_data == 'hook_constructor':
            self.app.get_dwarf().hook_java(item.text())
            return False
        elif action_data == 'hook_all':
            self.app.dwarf_api('hookAllJavaMethods', item.text())
            return False
        return True

    def item_double_clicked(self, item):
        p = JavaMethodsPanel(self.app)
        p.initialize_with_class(item.text())
        self.app.session_ui.add_tab(p, item.text().split('.')[-1])
        return False

    def on_enumeration_start(self):
        self.setRowCount(0)

    def on_enumeration_match(self, java_class):
        row = self.rowCount()
        self.insertRow(row)
        q = NotEditableTableWidgetItem(java_class)
        q.setFlags(Qt.ItemIsEnabled)
        self.setItem(row, 0, q)

    def on_enumeration_complete(self):
        self.sortByColumn(0, 0)
