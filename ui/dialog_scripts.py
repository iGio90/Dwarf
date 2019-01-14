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

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_table_base import TableBaseWidget


class ScriptsTable(TableBaseWidget):
    def __init__(self, app, dialog, *__args):
        super().__init__(app, *__args)
        self.dialog = dialog
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(['name', 'author', 'android', 'ios', 'description'])
        self.horizontalHeader().setStretchLastSection(True)

    def item_double_clicked(self, item):
        script_name = self.item(item.row(), 0).get_data()
        script_url = self.app.get_dwarf().get_scripts_manager().get_script(script_name)['script']
        script = self.app.get_dwarf().get_git().get_script(script_url)
        self.dialog.script = script
        self.dialog.accept()


class ScriptsDialog(QDialog):
    def __init__(self, app):
        super(ScriptsDialog, self).__init__(app)

        self.script = None

        self.setMinimumWidth(800)

        box = QVBoxLayout(self)
        table = ScriptsTable(app, self)
        table.setMinimumWidth(800)

        for script_name in sorted(app.get_dwarf().get_scripts_manager().get_scripts().keys()):
            script = app.get_dwarf().get_scripts_manager().get_script(script_name)
            info = script['info']
            row = table.rowCount()
            table.insertRow(row)
            q = NotEditableTableWidgetItem(info['name'])
            q.set_data(script_name)
            table.setItem(row, 0, q)
            if 'author' in info:
                q = NotEditableTableWidgetItem(info['author'])
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.lightGray)
                table.setItem(row, 1, q)
            if 'android' in info:
                q = NotEditableTableWidgetItem('X')
                q.setFlags(Qt.NoItemFlags)
                q.setTextAlignment(Qt.AlignCenter)
                q.setForeground(Qt.white)
                table.setItem(row, 2, q)
            if 'ios' in info:
                q = NotEditableTableWidgetItem('X')
                q.setFlags(Qt.NoItemFlags)
                q.setTextAlignment(Qt.AlignCenter)
                q.setForeground(Qt.white)
                table.setItem(row, 3, q)
            if 'description' in info:
                q = NotEditableTableWidgetItem(info['description'])
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.lightGray)
                table.setItem(row, 4, q)

        box.addWidget(table)
        self.setLayout(box)

    @staticmethod
    def pick(app):
        dialog = ScriptsDialog(app)
        result = dialog.exec_()
        return result == QDialog.Accepted, dialog.script
