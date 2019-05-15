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
from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QSplitter, QWidget, QVBoxLayout, QLabel

from ui.list_view import DwarfListView


class JavaFieldsWidget(DwarfListView):
    def __init__(self, explorer_panel, headers, is_native, *__args):
        super(JavaFieldsWidget, self).__init__(parent=explorer_panel.app)
        self.explorer_panel = explorer_panel
        self.is_native_fields_table = is_native

        self.doubleClicked.connect(self.item_double_clicked)

        self._model = QStandardItemModel(0, 2)
        for i in range(len(headers)):
            self._model.setHeaderData(i, Qt.Horizontal, headers[i])
        self.setModel(self._model)

    def add(self, name, value, handle=None, handle_class=None):
        if handle is not None:
            handle = {
                'handle': handle,
                'handle_class': handle_class
            }
            handle_item = QStandardItem(name)
            handle_item.setData(handle, Qt.UserRole + 1)
        else:
            handle_item = QStandardItem(name)
        self._model.appendRow([handle_item, QStandardItem(str(value))])

    def item_double_clicked(self, item):
        data = item.data(Qt.UserRole + 1)
        if data is not None:
            self.explorer_panel.set_handle(data)
        return False


class JavaMethodsWidget(DwarfListView):
    def __init__(self, explorer_panel, *__args):
        super(JavaMethodsWidget, self).__init__(parent=explorer_panel.app)
        self.explorer_panel = explorer_panel

        self._model = QStandardItemModel(0, 3)
        self._model.setHeaderData(0, Qt.Horizontal, 'Name')
        self._model.setHeaderData(1, Qt.Horizontal, 'Return')
        self._model.setHeaderData(2, Qt.Horizontal, 'Arguments')
        self.setModel(self._model)

    def add(self, name, ref):
        overloads = ref['overloads']
        for i in range(0, len(overloads)):
            overload = overloads[i]
            args = []
            for arg in overload['args']:
                args.append(arg['className'])
            self._model.appendRow([
                QStandardItem(name),
                QStandardItem(overload['return']['className']),
                QStandardItem('(%s)' % ', '.join(args)),
            ])


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

        self.methods.clear()
        self.fields.clear()
        self.native_fields.clear()
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
        self.handle_history = []
        self.methods._model.clear()
        self.fields._model.clear()
        self.native_fields._model.clear()

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
