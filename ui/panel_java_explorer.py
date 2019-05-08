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
from PyQt5.QtGui import QFont
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

    def add(self, name, value, handle=None, handle_class=None):
        row = self.rowCount()
        self.insertRow(row)
        if handle is not None:
            handle = {
                'handle': handle,
                'handle_class': handle_class
            }
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


class JavaExplorerPanel(QWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.handle_history = []

        box = QVBoxLayout()
        box.setContentsMargins(0, 0, 0, 0)

        self.clazz = QLabel()
        font = QFont()
        font.setBold(True)
        font.setPixelSize(19)
        self.clazz.setMaximumHeight(25)
        self.clazz.setFont(font)
        box.addWidget(self.clazz)

        splitter = QSplitter()
        splitter.setHandleWidth(1)

        left_col = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel('methods'))
        self.methods = JavaMethodsWidget(self)
        left_layout.addWidget(self.methods)
        left_col.setLayout(left_layout)
        splitter.addWidget(left_col)

        central_col = QWidget()
        central_layout = QVBoxLayout()
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.addWidget(QLabel('native fields'))
        self.native_fields = JavaFieldsWidget(self, ['name', 'value'], True)
        central_layout.addWidget(self.native_fields)
        central_col.setLayout(central_layout)
        splitter.addWidget(central_col)

        right_col = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(QLabel('fields'))
        self.fields = JavaFieldsWidget(self, ['name', 'class'], False)
        right_layout.addWidget(self.fields)
        right_col.setLayout(right_layout)
        splitter.addWidget(right_col)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 1)

        box.addWidget(splitter)
        self.setLayout(box)

    def _set_data(self, data):

        self.clazz.setText(data['class'])
        data = data['data']

        self.methods.setRowCount(0)
        self.fields.setRowCount(0)
        self.native_fields.setRowCount(0)
        for key in data:
            ref = data[key]
            if ref['type'] == 'function':
                if not key.startswith('$'):
                    self.methods.add(key, ref)
            elif ref['type'] == 'object':
                if not key.startswith('$'):
                    self.fields.add(key, ref['value'], ref['handle'], ref['handle_class'])
            else:
                if not key.startswith('$'):
                    self.native_fields.add(key, ref['value'])
        self.methods.sortByColumn(0, 0)
        self.native_fields.sortByColumn(0, 0)
        self.fields.sortByColumn(0, 0)

    def set_handle(self, handle):
        data = self.app.dwarf.dwarf_api('javaExplorer', handle)
        if data is None:
            return
        self.handle_history.append({'handle': handle})
        self._set_data(data)

    def set_handle_arg(self, arg):
        data = self.app.dwarf.dwarf_api('javaExplorer', arg)
        if data is None:
            return
        self.handle_history.append({'handle': arg})
        self._set_data(data)

    def clear_panel(self):
        self.handle_history.clear()
        self.methods.setRowCount(0)
        self.fields.setRowCount(0)
        self.native_fields.setRowCount(0)

    def back(self):
        if len(self.handle_history) < 2:
            return
        self.handle_history.pop()
        data = self.handle_history.pop(len(self.handle_history) - 1)['handle']
        if isinstance(data, int):
            self.set_handle_arg(data)
        else:
            self.set_handle(data)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.back()
        super(JavaExplorerPanel, self).keyPressEvent(event)
