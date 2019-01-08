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
from PyQt5.QtWidgets import QSplitter, QWidget, QVBoxLayout, QLabel, QHeaderView

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_table_base import TableBaseWidget


class HandleWidget(NotEditableTableWidgetItem):
    def __init__(self, handle, *__args):
        super().__init__(*__args)
        self.handle = handle


class JavaFieldsWidget(TableBaseWidget):
    def __init__(self, explorer_panel, headers, is_native, *__args):
        super().__init__(explorer_panel.app, 0, 2)
        self.explorer_panel = explorer_panel
        self.is_native_fields_table = is_native

        self.setHorizontalHeaderLabels(headers)
        self.horizontalHeader().setStretchLastSection(True)

    def add(self, name, value, handle=None):
        row = self.rowCount()
        self.insertRow(row)
        if handle is not None:
            self.setItem(row, 0, HandleWidget(handle, name))
        else:
            self.setItem(row, 0, NotEditableTableWidgetItem(name))
        self.setItem(row, 1, NotEditableTableWidgetItem(str(value)))

    def item_double_clicked(self, item):
        if isinstance(item, HandleWidget) and item.handle is not None:
            self.explorer_panel.set_handle(item.handle)
        return False


class JavaMethodsWidget(TableBaseWidget):
    def __init__(self, explorer_panel, *__args):
        super().__init__(explorer_panel.app, 0, 3)
        self.explorer_panel = explorer_panel

        self.setHorizontalHeaderLabels(['name', 'return', 'arguments'])
        self.horizontalHeader().setStretchLastSection(True)
        self.setColumnWidth(0, 200)
        self.setColumnWidth(1, 150)

    def add(self, name, ref):
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, NotEditableTableWidgetItem(name))
        overloads = ref['overloads']
        for i in range(0, len(overloads)):
            overload = overloads[i]
            if i > 0:
                row = self.rowCount()
                self.insertRow(row)
            args = []
            for arg in overload['args']:
                args.append(arg['className'])
            self.setItem(row, 1, NotEditableTableWidgetItem(overload['return']['className']))
            self.setItem(row, 2, NotEditableTableWidgetItem('(%s)' % ', '.join(args)))


class JavaExplorerPanel(QSplitter):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.setHandleWidth(1)

        left_col = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel('methods'))
        self.methods = JavaMethodsWidget(self)
        left_layout.addWidget(self.methods)
        left_col.setLayout(left_layout)
        self.addWidget(left_col)

        central_col = QWidget()
        central_layout = QVBoxLayout()
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.addWidget(QLabel('native fields'))
        self.native_fields = JavaFieldsWidget(self, ['name', 'value'], True)
        central_layout.addWidget(self.native_fields)
        central_col.setLayout(central_layout)
        self.addWidget(central_col)

        right_col = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(QLabel('fields'))
        self.fields = JavaFieldsWidget(self, ['name', 'class'], False)
        right_layout.addWidget(self.fields)
        right_col.setLayout(right_layout)
        self.addWidget(right_col)

        self.setStretchFactor(0, 2)
        self.setStretchFactor(1, 1)
        self.setStretchFactor(2, 1)

    def _set_data(self, data):
        if data is None:
            return
        if not self.isVisible():
            self.app.get_session_ui().show_java_panel()

        self.methods.setRowCount(0)
        self.fields.setRowCount(0)
        self.native_fields.setRowCount(0)
        for key in data:
            ref = data[key]
            if ref['type'] == 'function':
                if not key.startswith('$'):
                    self.methods.add(key, ref)
            elif ref['type'] == 'object':
                self.fields.add(key, ref['value'], ref['handle'])
            else:
                self.native_fields.add(key, ref['value'])
        self.methods.sortByColumn(0, 0)
        self.native_fields.sortByColumn(0, 0)
        self.fields.sortByColumn(0, 0)

    def set_handle(self, handle):
        data = self.app.dwarf_api('javaExplorer', handle)
        self._set_data(data)

    def set_handle_arg(self, arg):
        data = self.app.dwarf_api('javaExplorer', arg)
        self._set_data(data)
