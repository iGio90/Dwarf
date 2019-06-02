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

from ui.widgets.list_view import DwarfListView


class JavaFieldsWidget(DwarfListView):
    def __init__(self, explorer_panel, headers, is_native, *__args):
        super(JavaFieldsWidget, self).__init__(parent=explorer_panel.app)
        self.explorer_panel = explorer_panel
        self.is_native_fields_table = is_native

        self.doubleClicked.connect(self.item_double_clicked)

        self._fields_model = QStandardItemModel(0, 2)
        if headers and len(headers) == 2:
            self._fields_model.setHeaderData(0, Qt.Horizontal, headers[0])
            self._fields_model.setHeaderData(1, Qt.Horizontal, headers[1])
        else:
            self._fields_model.setHeaderData(0, Qt.Horizontal, 'Name')
            self._fields_model.setHeaderData(1, Qt.Horizontal, 'Value')
        self.setModel(self._fields_model)

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
        self._fields_model.appendRow([handle_item, QStandardItem(str(value))])

    def item_double_clicked(self, item):
        data = item.data(Qt.UserRole + 1)
        if data is not None:
            self.explorer_panel.set_handle(data)
        return False


class JavaMethodsWidget(DwarfListView):
    def __init__(self, explorer_panel, *__args):
        super(JavaMethodsWidget, self).__init__(parent=explorer_panel.app)
        self.explorer_panel = explorer_panel

        self._methods_model = QStandardItemModel(0, 3)
        self._methods_model.setHeaderData(0, Qt.Horizontal, 'Name')
        self._methods_model.setHeaderData(1, Qt.Horizontal, 'Return')
        self._methods_model.setHeaderData(2, Qt.Horizontal, 'Arguments')
        self.setModel(self._methods_model)

    def add(self, name, ref):
        overloads = ref['overloads']
        for i in range(0, len(overloads)):
            overload = overloads[i]
            args = []
            for arg in overload['args']:
                args.append(arg['className'])
            self._methods_model.appendRow([
                QStandardItem(name),
                QStandardItem(overload['return']['className']),
                QStandardItem('(%s)' % ', '.join(args)),
            ])


class JavaExplorerPanel(QWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.handle_history = []
        self.setContentsMargins(0, 0, 0, 0)

        # main wrapper
        main_wrap = QVBoxLayout()
        main_wrap.setContentsMargins(1, 1, 1, 1)

        # create label
        wrapping_wdgt = QWidget()
        self.clazz = QLabel(wrapping_wdgt)
        self.clazz.setContentsMargins(10, 10, 10, 10)

        font = QFont()
        font.setBold(True)
        font.setPixelSize(19)
        self.clazz.setFont(font)
        self.clazz.setAttribute(Qt.WA_TranslucentBackground, True) # keep this
        wrapping_wdgt.setMaximumHeight(self.clazz.height() + 20)
        # add to mainwrapper
        main_wrap.addWidget(wrapping_wdgt)

        # create splitter
        splitter = QSplitter()
        splitter.setContentsMargins(0, 0, 0, 0)

        # left side
        left_col = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel('methods'.upper())
        font = label.font()
        font.setBold(True)
        label.setFont(font)
        label.setStyleSheet('color: #ef5350;')
        label.setContentsMargins(10, 0, 10, 2)
        label.setAttribute(Qt.WA_TranslucentBackground, True) # keep this
        left_layout.addWidget(label)
        self.methods = JavaMethodsWidget(self)
        left_layout.addWidget(self.methods)
        left_col.setLayout(left_layout)
        splitter.addWidget(left_col)

        # middle
        central_col = QWidget()
        central_layout = QVBoxLayout()
        central_layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel('native fields'.upper())
        label.setFont(font)
        label.setStyleSheet('color: #ef5350;')
        label.setContentsMargins(10, 0, 10, 2)
        label.setAttribute(Qt.WA_TranslucentBackground, True) # keep this
        central_layout.addWidget(label)
        self.native_fields = JavaFieldsWidget(self, ['name', 'value'], True)
        central_layout.addWidget(self.native_fields)
        central_col.setLayout(central_layout)
        splitter.addWidget(central_col)

        # right side
        right_col = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel('fields'.upper())
        label.setFont(font)
        label.setContentsMargins(10, 0, 10, 2)
        label.setAttribute(Qt.WA_TranslucentBackground, True) # keep this
        label.setStyleSheet('color: #ef5350;')
        right_layout.addWidget(label)
        self.fields = JavaFieldsWidget(self, ['name', 'class'], False)
        right_layout.addWidget(self.fields)
        right_col.setLayout(right_layout)
        splitter.addWidget(right_col)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 1)

        main_wrap.addWidget(splitter)
        main_wrap.setSpacing(0)
        self.setLayout(main_wrap)

    def _set_data(self, data):
        if 'class' not in data:
            return

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
                if ref['handle'] is not None:
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
        self.clazz.setText('')
        self.handle_history = []
        self.methods.clear()
        self.fields.clear()
        self.native_fields.clear()

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
