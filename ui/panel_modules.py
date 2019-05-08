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

import json

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QHeaderView,
                             QMenu)
from lib import utils
from ui.list_view import DwarfListView


class ModulesPanel(QWidget):
    """ ModulesPanel

        Signals:
            onAddHook([ptr, funcname]) - MenuItem AddHook
            onDumpBinary([ptr, size#int]) - MenuItem DumpBinary
            onModuleSelected([ptr, size#int]) - ModuleDoubleClicked
            onModuleFuncSelected(ptr) - FunctionDoubleClicked
    """
    # pylint: disable=too-many-instance-attributes

    onAddHook = pyqtSignal(list, name='onAddHook')
    onDumpBinary = pyqtSignal(list, name='onDumpBinary')
    onModuleSelected = pyqtSignal(list, name='onModuleSelected')
    onModuleFuncSelected = pyqtSignal(str, name='onModuleFuncSelected')

    def __init__(self, parent=None):  # pylint: disable=too-many-statements
        super(ModulesPanel, self).__init__(parent)
        self._app_window = parent

        if self._app_window.dwarf is None:
            print('ModulesPanel created before Dwarf exists')
            return

        self._app_window.dwarf.onSetModules.connect(self.set_modules)

        self._uppercase_hex = True

        # setup models
        self.modules_list = None
        self.modules_model = QStandardItemModel(0, 4, self)
        self.modules_model.setHeaderData(0, Qt.Horizontal, 'Name')
        self.modules_model.setHeaderData(1, Qt.Horizontal, 'Base')
        self.modules_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.modules_model.setHeaderData(2, Qt.Horizontal, 'Size')
        self.modules_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.modules_model.setHeaderData(3, Qt.Horizontal, 'Path')

        self.imports_list = None
        self.imports_model = QStandardItemModel(0, 4, self)
        self.imports_model.setHeaderData(0, Qt.Horizontal, 'Import')
        self.imports_model.setHeaderData(1, Qt.Horizontal, 'Address')
        self.imports_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.imports_model.setHeaderData(2, Qt.Horizontal, 'Module')
        self.imports_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.imports_model.setHeaderData(3, Qt.Horizontal, 'Type')

        self.exports_list = None
        self.exports_model = QStandardItemModel(0, 3, self)
        self.exports_model.setHeaderData(0, Qt.Horizontal, 'Export')
        self.exports_model.setHeaderData(1, Qt.Horizontal, 'Address')
        self.exports_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.exports_model.setHeaderData(2, Qt.Horizontal, 'Type')

        self.symbols_list = None
        self.symbols_model = QStandardItemModel(0, 3, self)
        self.symbols_model.setHeaderData(0, Qt.Horizontal, 'Export')
        self.symbols_model.setHeaderData(1, Qt.Horizontal, 'Address')
        self.symbols_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.symbols_model.setHeaderData(2, Qt.Horizontal, 'Type')

        # setup ui
        main_wrapper = QVBoxLayout()
        main_wrapper.setContentsMargins(0, 0, 0, 0)
        h_box = QHBoxLayout()
        self.modules_list = DwarfListView()
        self.modules_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.modules_list.customContextMenuRequested.connect(
            self._on_modules_contextmenu)
        self.modules_list.setEditTriggers(self.modules_list.NoEditTriggers)
        self.modules_list.clicked.connect(self._module_clicked)
        self.modules_list.doubleClicked.connect(self._module_dblclicked)
        self.modules_list.setModel(self.modules_model)
        self.modules_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self.modules_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self.modules_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)
        h_box.addWidget(self.modules_list)
        self.modules_list.selectionModel().selectionChanged.connect(
            self._module_clicked)

        hv_box = QVBoxLayout()
        self.imports_list = DwarfListView()
        self.imports_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.imports_list.customContextMenuRequested.connect(
            self._on_imports_contextmenu)
        self.imports_list.setEditTriggers(self.modules_list.NoEditTriggers)
        self.imports_list.doubleClicked.connect(self._import_dblclicked)
        self.imports_list.setModel(self.imports_model)
        self.imports_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self.imports_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self.imports_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)
        self.imports_list.setVisible(False)
        self.exports_list = DwarfListView()
        self.exports_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.exports_list.customContextMenuRequested.connect(
            self._on_exports_contextmenu)
        self.exports_list.setEditTriggers(self.modules_list.NoEditTriggers)
        self.exports_list.doubleClicked.connect(self._export_dblclicked)
        self.exports_list.setModel(self.exports_model)
        self.exports_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self.exports_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self.exports_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)
        self.exports_list.setVisible(False)
        self.symbols_list = DwarfListView()
        self.symbols_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.symbols_list.doubleClicked.connect(self._symbol_dblclicked)
        self.symbols_list.setModel(self.symbols_model)
        self.symbols_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self.symbols_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self.symbols_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)
        self.symbols_list.setVisible(False)
        hv_box.addWidget(self.imports_list)
        hv_box.addWidget(self.exports_list)
        hv_box.addWidget(self.symbols_list)
        h_box.addLayout(hv_box)
        main_wrapper.addLayout(h_box)
        self.setLayout(main_wrapper)

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def uppercase_hex(self):
        """ HexDisplayStyle
        """
        return self._uppercase_hex

    @uppercase_hex.setter
    def uppercase_hex(self, value):
        """ HexDisplayStyle
        """
        if isinstance(value, bool):
            self._uppercase_hex = value
        elif isinstance(value, str):
            self._uppercase_hex = (value == 'upper')

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def set_modules(self, modules):
        """ Fills the ModulesList with data
        """
        self.modules_list.clear()
        for module in modules:
            name = QStandardItem()
            name.setTextAlignment(Qt.AlignLeft)
            name.setText(module['name'])

            base = QStandardItem()
            base.setTextAlignment(Qt.AlignCenter)

            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'

            base.setText(str_fmt.format(int(module['base'], 16)))

            size = QStandardItem()
            size.setTextAlignment(Qt.AlignRight)
            size.setText("{0:,d}".format(int(module['size'])))

            path = QStandardItem()
            path.setTextAlignment(Qt.AlignLeft)
            path.setText(module['path'])

            self.modules_model.appendRow([name, base, size, path])

    def update_modules(self):
        """ DwarfApiCall updateModules
        """
        return self._app_window.dwarf.dwarf_api('updateModules')

    def set_imports(self, imports):
        """ Fills the ImportsList with data
        """
        self.imports_list.clear()
        for import_ in imports:
            name = QStandardItem()
            name.setTextAlignment(Qt.AlignLeft)
            name.setText(import_['name'])

            address = QStandardItem()
            address.setTextAlignment(Qt.AlignCenter)

            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'

            address.setText(str_fmt.format(int(import_['address'], 16)))

            module = QStandardItem()
            if 'module' in import_:
                module.setTextAlignment(Qt.AlignLeft)
                module.setText(import_['module'])

            type_ = QStandardItem()
            if 'type' in import_:
                type_.setTextAlignment(Qt.AlignLeft)
                type_.setText(import_['type'])

            self.imports_model.appendRow([name, address, module, type_])

    def set_exports(self, exports):
        """ Fills the ExportsList with data
        """
        self.exports_list.clear()
        for export in exports:
            name = QStandardItem()
            name.setTextAlignment(Qt.AlignLeft)
            name.setText(export['name'])

            address = QStandardItem()
            address.setTextAlignment(Qt.AlignCenter)
            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'
            address.setText(str_fmt.format(int(export['address'], 16)))

            type_ = QStandardItem()
            type_.setTextAlignment(Qt.AlignLeft)
            type_.setText(export['type'])

            self.exports_model.appendRow([name, address, type_])

    def set_symbols(self, symbols):
        """ Fills the SymbolsList with data
        """
        self.symbols_list.clear()
        for symbol in symbols:
            name = QStandardItem()
            name.setTextAlignment(Qt.AlignLeft)
            name.setText(symbol['name'])

            address = QStandardItem()
            address.setTextAlignment(Qt.AlignCenter)
            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'
            address.setText(str_fmt.format(int(symbol['address'], 16)))

            type_ = QStandardItem()
            type_.setTextAlignment(Qt.AlignLeft)
            type_.setText(symbol['type'])

            self.symbols_model.appendRow([name, address, type_])

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _module_clicked(self):
        """ Module Clicked updates imports/exports/symbols
        """
        module_index = self.modules_list.selectionModel().currentIndex().row()
        module = self.modules_model.item(module_index, 0)  # module name
        if module is None:
            return

        imports = self._app_window.dwarf.dwarf_api('enumerateImports',
                                                   module.text())
        if imports and (imports is not None):
            imports = json.loads(imports)
            if imports:
                self.set_imports(imports)
                self.imports_list.setVisible(True)
            else:
                self.imports_list.setVisible(False)

        exports = self._app_window.dwarf.dwarf_api('enumerateExports',
                                                   module.text())
        if exports and exports is not None:
            exports = json.loads(exports)
            if exports:
                self.set_exports(exports)
                self.exports_list.setVisible(True)
            else:
                self.exports_list.setVisible(False)

        symbols = self._app_window.dwarf.dwarf_api('enumerateSymbols',
                                                   module.text())
        if symbols and symbols is not None:
            symbols = json.loads(symbols)
            if symbols:
                self.set_symbols(symbols)
                self.symbols_list.setVisible(True)
            else:
                self.symbols_list.setVisible(False)

    def _module_dblclicked(self):
        """ Module DoubleClicked
        """
        module_index = self.modules_list.selectionModel().currentIndex().row()
        base = self.modules_model.item(module_index, 1).text()
        size = self.modules_model.item(module_index, 2).text().replace(',', '')
        self.onModuleSelected.emit([base, size])

    def _import_dblclicked(self):
        """ ImportFunction DoubleClicked
        """
        index = self.imports_list.selectionModel().currentIndex().row()
        addr = self.imports_model.item(index, 1).text()
        self.onModuleFuncSelected.emit(addr)

    def _export_dblclicked(self):
        """ ExportFunction DoubleClicked
        """
        index = self.exports_list.selectionModel().currentIndex().row()
        addr = self.exports_model.item(index, 1).text()
        self.onModuleFuncSelected.emit(addr)

    def _symbol_dblclicked(self):
        """ Symbol DoubleClicked
        """
        index = self.symbols_list.selectionModel().currentIndex().row()
        addr = self.symbols_model.item(index, 1).text()
        self.onModuleFuncSelected.emit(addr)

    def _on_modules_contextmenu(self, pos):
        """ Modules ContextMenu
        """
        index = self.modules_list.indexAt(pos).row()
        glbl_pt = self.modules_list.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            context_menu.addAction(
                'Dump Binary', lambda: self._on_dumpmodule(
                    self.modules_model.item(index, 1).text(),
                    self.modules_model.item(index, 2).text()))
            context_menu.addAction(
                'Copy Address', lambda: utils.copy_hex_to_clipboard(
                    self.modules_model.item(index, 1).text()))
            context_menu.addSeparator()
            context_menu.addAction(
                'Copy Name', lambda: utils.copy_str_to_clipboard(
                    self.modules_model.item(index, 0).text()))
            context_menu.addAction(
                'Copy Path', lambda: utils.copy_str_to_clipboard(
                    self.modules_model.item(index, 3).text()))
            context_menu.addSeparator()

        context_menu.addAction('Refresh', self.update_modules)
        context_menu.exec_(glbl_pt)

    def _on_imports_contextmenu(self, pos):
        """ ImportList ContextMenu
        """
        index = self.imports_list.indexAt(pos).row()
        if index != -1:
            glbl_pt = self.imports_list.mapToGlobal(pos)
            context_menu = QMenu(self)
            func_name = self.imports_model.item(index, 0).text()
            addr = self.imports_model.item(index, 1).text()
            context_menu.addAction(
                'Add Hook', lambda: self._add_hook(addr, func_name))
            context_menu.addSeparator()
            context_menu.addAction(
                'Copy Address', lambda: utils.copy_hex_to_clipboard(
                    self.imports_model.item(index, 1).text()))
            context_menu.addSeparator()
            context_menu.addAction(
                'Copy FunctionName', lambda: utils.copy_str_to_clipboard(
                    func_name))
            context_menu.addAction(
                'Copy ModuleName', lambda: utils.copy_str_to_clipboard(
                    self.imports_model.item(index, 2).text()))
            context_menu.exec_(glbl_pt)

    def _on_exports_contextmenu(self, pos):
        """ ExportsList ContextMenu
        """
        index = self.exports_list.indexAt(pos).row()
        if index != -1:
            glbl_pt = self.exports_list.mapToGlobal(pos)
            context_menu = QMenu(self)
            func_name = self.exports_model.item(index, 0).text()
            addr = self.exports_model.item(index, 1).text()
            context_menu.addAction(
                'Add Hook', lambda: self._add_hook(addr, func_name))
            context_menu.addSeparator()
            context_menu.addAction(
                'Copy Address', lambda: utils.copy_hex_to_clipboard(
                    self.exports_model.item(index, 1).text()))
            context_menu.addSeparator()
            context_menu.addAction(
                'Copy FunctionName', lambda: utils.copy_str_to_clipboard(
                    func_name))
            context_menu.exec_(glbl_pt)

    def _on_dumpmodule(self, ptr, size):
        """ MenuItem DumpBinary
        """
        if isinstance(ptr, int):
            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'
            ptr = str_fmt.format(ptr)

        size = size.replace(',', '')
        self.onDumpBinary.emit([ptr, size])

    def _add_hook(self, ptr, name=None):
        """ MenuItem AddHook
        """
        if name is None:
            name = ptr
        if isinstance(ptr, str):
            if ptr.startswith('0x') or ptr.startswith('#'):
                self.onAddHook.emit([ptr, name])
        elif isinstance(ptr, int):
            str_fmt = '0x{0:x}'
            self.onAddHook.emit(str_fmt.format([ptr, name]))
