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
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QSplitter, QWidget, QVBoxLayout, QLabel, QHeaderView

from dwarf_debugger.ui.widgets.list_view import DwarfListView


class JavaExplorerPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self._app_window = parent

        self._handle_history = []

        self._setup_ui()
        self._setup_models()

    def _setup_ui(self):
        self.setContentsMargins(0, 0, 0, 0)

        top_font = QFont()
        top_font.setBold(True)
        top_font.setPixelSize(19)

        # main wrapper
        main_wrapper = QVBoxLayout()
        main_wrapper.setContentsMargins(1, 1, 1, 1)

        # wrapwdgt
        wrap_wdgt = QWidget()
        self._top_class_name = QLabel(wrap_wdgt)
        self._top_class_name.setContentsMargins(10, 10, 10, 10)
        self._top_class_name.setAttribute(Qt.WA_TranslucentBackground,
                                          True)  # keep this
        self._top_class_name.setFont(top_font)
        self._top_class_name.setStyleSheet('color: #ef5350;')
        wrap_wdgt.setMaximumHeight(self._top_class_name.height() + 20)

        main_wrapper.addWidget(wrap_wdgt)

        # left list
        left_wrap_wdgt = QWidget()

        left_v_box = QVBoxLayout(left_wrap_wdgt)
        left_v_box.setContentsMargins(0, 0, 0, 0)

        methods_label = QLabel('METHODS')
        font = methods_label.font()
        font.setBold(True)
        methods_label.setFont(font)
        methods_label.setContentsMargins(10, 0, 10, 2)
        methods_label.setAttribute(Qt.WA_TranslucentBackground,
                                   True)  # keep this
        left_v_box.addWidget(methods_label)

        self._methods_list = DwarfListView()
        left_v_box.addWidget(self._methods_list)

        # center list
        center_wrap_wdgt = QWidget()

        center_v_box = QVBoxLayout(center_wrap_wdgt)
        center_v_box.setContentsMargins(0, 0, 0, 0)

        methods_label = QLabel('NATIVE FIELDS')
        methods_label.setFont(font)
        methods_label.setContentsMargins(10, 0, 10, 2)
        methods_label.setAttribute(Qt.WA_TranslucentBackground,
                                   True)  # keep this
        center_v_box.addWidget(methods_label)

        self._native_fields_list = DwarfListView()
        self._native_fields_list.doubleClicked.connect(
            self._on_native_field_dblclicked)
        center_v_box.addWidget(self._native_fields_list)

        # right list
        right_wrap_wdgt = QWidget()

        right_v_box = QVBoxLayout(right_wrap_wdgt)
        right_v_box.setContentsMargins(0, 0, 0, 0)

        methods_label = QLabel('FIELDS')
        methods_label.setFont(font)
        methods_label.setContentsMargins(10, 0, 10, 2)
        methods_label.setAttribute(Qt.WA_TranslucentBackground,
                                   True)  # keep this
        right_v_box.addWidget(methods_label)

        self._fields_list = DwarfListView()
        self._fields_list.doubleClicked.connect(self._on_field_dblclicked)
        right_v_box.addWidget(self._fields_list)

        # main splitter
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setContentsMargins(0, 0, 0, 0)
        main_splitter.addWidget(left_wrap_wdgt)
        main_splitter.addWidget(center_wrap_wdgt)
        main_splitter.addWidget(right_wrap_wdgt)
        main_splitter.setSizes([250, 100, 100])

        main_wrapper.addWidget(main_splitter)
        main_wrapper.setSpacing(0)
        self.setLayout(main_wrapper)

    def _setup_models(self):
        # left list
        self._methods_model = QStandardItemModel(0, 3)
        self._methods_model.setHeaderData(0, Qt.Horizontal, 'Name')
        self._methods_model.setHeaderData(1, Qt.Horizontal, 'Return')
        self._methods_model.setHeaderData(2, Qt.Horizontal, 'Arguments')
        self._methods_list.setModel(self._methods_model)
        self._methods_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._methods_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        # center list
        self._native_fields_model = QStandardItemModel(0, 2)
        self._native_fields_model.setHeaderData(0, Qt.Horizontal, 'Name')
        self._native_fields_model.setHeaderData(1, Qt.Horizontal, 'Value')
        self._native_fields_list.setModel(self._native_fields_model)
        self._native_fields_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        # right list
        self._fields_model = QStandardItemModel(0, 2)
        self._fields_model.setHeaderData(0, Qt.Horizontal, 'Name')
        self._fields_model.setHeaderData(1, Qt.Horizontal, 'Class')
        self._fields_list.setModel(self._fields_model)
        self._fields_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def _set_data(self, data):
        if 'class' not in data:
            return

        self._top_class_name.setText(data['class'])
        data = data['data']

        self._methods_list.clear()
        self._native_fields_list.clear()
        self._fields_list.clear()

        for key in data:
            ref = data[key]
            if ref['type'] == 'function':
                if not key.startswith('$'):
                    self._add_method(key, ref)
            elif ref['type'] == 'object':
                if ref['handle'] is not None:
                    if not key.startswith('$'):
                        self._add_field(key, ref['value'], ref['handle'],
                                        ref['handle_class'])
            else:
                if not key.startswith('$'):
                    self._add_field(key, ref['value'], is_native=True)

        self._methods_list.sortByColumn(0, 0)
        self._native_fields_list.sortByColumn(0, 0)
        self._fields_list.sortByColumn(0, 0)

    def _add_method(self, name, ref):
        ref_overloads = ref['overloads']
        for _, ref_overload in enumerate(ref_overloads):
            args = []

            if 'args' in ref_overload:
                for arg in ref_overload['args']:
                    if 'className' in arg:
                        args.append(arg['className'])

            self._methods_model.appendRow([
                QStandardItem(name),
                QStandardItem(ref_overload['return']['className']),
                QStandardItem('(%s)' % ', '.join(args)),
            ])

    def _add_field(self, name, value, handle=None, handle_class=None, is_native=False):
        if handle:
            handle = {'handle': handle, 'handle_class': handle_class}
            handle_item = QStandardItem(name)
            handle_item.setData(handle, Qt.UserRole + 1)
        else:
            handle_item = QStandardItem(name)

        if not is_native:
            self._fields_model.appendRow(
                [handle_item, QStandardItem(str(value))])
        else:
            self._native_fields_model.appendRow(
                [handle_item, QStandardItem(str(value))])

    def _set_handle(self, handle):
        data = self._app_window.dwarf.dwarf_api('jvmExplorer', handle)
        if not data:
            return
        self._handle_history.append({'handle': handle})
        self._set_data(data)

    def _set_handle_arg(self, arg):
        data = self._app_window.dwarf.dwarf_api('jvmExplorer', arg)
        if not data:
            return
        self._handle_history.append({'handle': arg})
        self._set_data(data)

    def init(self):
        data = self._app_window.dwarf.dwarf_api('jvmExplorer')
        if not data:
            return
        self._handle_history.append({'handle': None})
        self._set_data(data)

    def clear_panel(self):
        self._top_class_name.setText('')
        self._handle_history = []
        self._methods_list.clear()
        self._native_fields_list.clear()
        self._fields_list.clear()

    def _back(self):
        if len(self._handle_history) < 2:
            return
        self._handle_history.pop()
        data = self._handle_history.pop(len(self._handle_history) - 1)['handle']
        if isinstance(data, int):
            self._set_handle_arg(data)
        else:
            if data is not None:
                self._set_handle(data)
            else:
                self.init()

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_field_dblclicked(self, _):
        field_row = self._fields_list.selectionModel().currentIndex().row()
        if field_row >= 0:
            field_handle = self._fields_model.item(field_row, 0).data(Qt.UserRole + 1)
            if field_handle:
                self._set_handle(field_handle)

    def _on_native_field_dblclicked(self, _):
        field_row = self._native_fields_list.selectionModel().currentIndex().row()
        if field_row:
            field_handle = self._native_fields_model.item(
                field_row, 0).data(Qt.UserRole + 1)
            if field_handle:
                self._set_handle(field_handle)

    def keyPressEvent(self, event): # pylint: disable=invalid-name
        key = event.key()
        if key == Qt.Key_Backspace or key == Qt.Key_Escape:
            self._back()

        return super().keyPressEvent(event)
