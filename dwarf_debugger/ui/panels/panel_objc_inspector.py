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
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QHeaderView, QHBoxLayout, QMenu

from dwarf_debugger.ui.widgets.list_view import DwarfListView


class ObjCInspector(QWidget):
    """ ObjC Class/Methods Lists
    """

    def __init__(self, parent=None):
        super(ObjCInspector, self).__init__(parent)

        self._app_window = parent

        self._app_window.dwarf.onEnumerateObjCModules.connect(self._on_enumerate_objc_modules)
        self._app_window.dwarf.onEnumerateObjCMethodsStart.connect(
            self._on_method_enumeration_start)
        self._app_window.dwarf.onEnumerateObjCMethodsMatch.connect(
            self._on_method_enumeration_match)
        self._app_window.dwarf.onEnumerateObjCMethodsComplete.connect(
            self._on_method_enumeration_complete)

        self._app_window.dwarf.onEnumerateObjCClassesStart.connect(
            self._on_class_enumeration_start)
        self._app_window.dwarf.onEnumerateObjCClassesMatch.connect(
            self._on_class_enumeration_match)
        self._app_window.dwarf.onEnumerateObjCClassesComplete.connect(
            self._on_class_enumeration_complete)

        self._ObjC_modules = DwarfListView(self)
        self._ObjCmodule_model = QStandardItemModel(0, 1)
        self._ObjCmodule_model.setHeaderData(0, Qt.Horizontal, 'Modules')
        self._ObjC_modules.setModel(self._ObjCmodule_model)
        self._ObjC_modules.selectionModel().selectionChanged.connect(
            self._module_clicked)
        self._ObjC_modules.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._ObjC_modules.setContextMenuPolicy(Qt.CustomContextMenu)
        self._ObjC_modules.customContextMenuRequested.connect(
            self._on_module_contextmenu)
        self._ObjC_modules.doubleClicked.connect(self._class_dblclicked)

        self._ObjC_classes = DwarfListView(self)
        self._ObjCclass_model = QStandardItemModel(0, 1)
        self._ObjCclass_model.setHeaderData(0, Qt.Horizontal, 'Class')
        self._ObjC_classes.setModel(self._ObjCclass_model)
        self._ObjC_classes.selectionModel().selectionChanged.connect(
            self._class_clicked)
        self._ObjC_classes.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._ObjC_classes.setContextMenuPolicy(Qt.CustomContextMenu)
        self._ObjC_classes.customContextMenuRequested.connect(
            self._on_class_contextmenu)
        self._ObjC_classes.doubleClicked.connect(self._class_dblclicked)

        self._ObjC_methods = DwarfListView(self)
        self._ObjCmethod_model = QStandardItemModel(0, 1)
        self._ObjCmethod_model.setHeaderData(0, Qt.Horizontal, 'Method')
        self._ObjC_methods.setModel(self._ObjCmethod_model)
        self._ObjC_methods.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._ObjC_methods.setContextMenuPolicy(Qt.CustomContextMenu)
        self._ObjC_methods.customContextMenuRequested.connect(
            self._on_method_contextmenu)
        self._ObjC_methods.doubleClicked.connect(self._method_dblclicked)

        h_box = QHBoxLayout()
        h_box.setContentsMargins(0, 0, 0, 0)
        h_box.addWidget(self._ObjC_modules)
        h_box.addWidget(self._ObjC_classes)
        h_box.addWidget(self._ObjC_methods)
        self.setLayout(h_box)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def update_classes(self, module_name):
        """ Refresh Classeslist
        """
        self._app_window.dwarf.dwarf_api('enumerateObjCClasses', module_name)

    def update_methods(self, class_name):
        """ Refresh Methodslist
        """
        if class_name:
            self._app_window.dwarf.dwarf_api('enumerateObjCMethods',
                                             class_name)

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _module_clicked(self):
        index = self._ObjC_modules.selectionModel().currentIndex().row()
        _module = self._ObjCmodule_model.item(index, 0)
        if _module is None:
            return

        self._app_window.dwarf.dwarf_api('enumerateObjCClasses', _module.text())

    def _class_clicked(self):
        index = self._ObjC_classes.selectionModel().currentIndex().row()
        _class = self._ObjCclass_model.item(index, 0)
        if _class is None:
            return

        self._app_window.dwarf.dwarf_api('enumerateObjCMethods', _class.text())

    def _on_class_enumeration_start(self):
        self._ObjC_classes.clear()
        self._ObjC_methods.clear()

    def _on_method_enumeration_start(self):
        self._ObjC_methods.clear()

    def _on_class_enumeration_match(self, ObjC_class):
        _class_name = QStandardItem()
        _class_name.setText(ObjC_class)
        self._ObjCclass_model.appendRow(_class_name)

    def _on_method_enumeration_match(self, ObjC_method):
        _method_name = QStandardItem()
        _method_name.setText(ObjC_method)
        self._ObjCmethod_model.appendRow(_method_name)

    def _on_class_enumeration_complete(self):
        self._ObjC_classes.sortByColumn(0, 0)

    def _on_method_enumeration_complete(self):
        self._ObjC_methods.sortByColumn(0, 0)

    def _class_dblclicked(self):
        """ Class DoubleClicked
        """
        index = self._ObjC_classes.selectionModel().currentIndex().row()
        if index:
            class_item = self._ObjCclass_model.item(index, 0)
            if class_item:
                class_name = class_item.text()
                if class_name:
                    self._breakpoint_class(class_name)

    def _method_dblclicked(self):
        """ Function DoubleClicked
        """
        class_index = self._ObjC_classes.selectionModel().currentIndex().row()
        method_index = self._ObjC_methods.selectionModel().currentIndex().row()
        if class_index and method_index:
            class_item = self._ObjCclass_model.item(class_index, 0)
            method_item = self._ObjCmethod_model.item(method_index, 0)
            if class_item and method_item:
                class_name = class_item.text()
                method_name = method_item.text()
                if class_name and method_name:
                    self._app_window.dwarf.breakpoint_objc(class_name + '.'
                                                           + method_name)

    def _breakpoint_class(self, class_name):
        if class_name:
            self._app_window.dwarf.breakpoint_objc(class_name)

    def _breakpoint_class_functions(self, class_name):
        if class_name:
            self._app_window.dwarf.dwarf_api('breakpointAllObjCMethods', class_name)

    def _on_class_contextmenu(self, pos):
        """ Class ContextMenu
        """
        index = self._ObjC_classes.indexAt(pos).row()
        glbl_pt = self._ObjC_classes.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            context_menu.addAction(
                'Breakpoint constructor', lambda: self._breakpoint_class(
                    self._ObjCclass_model.item(index, 0).text()))
            context_menu.addAction(
                'Breakpoint all methods', lambda: self._breakpoint_class_functions(
                    self._ObjCclass_model.item(index, 0).text()))
            context_menu.addSeparator()

            if self._ObjC_classes.search_enabled:
                context_menu.addSeparator()
                context_menu.addAction(
                    'Search', self._ObjC_classes._on_cm_search)

        context_menu.addAction('Refresh', self._cm_refresh_classes)
        context_menu.exec_(glbl_pt)

    def _breakpoint_method(self, method_name):
        class_index = self._ObjC_classes.selectionModel().currentIndex().row()
        if class_index:
            class_item = self._ObjCclass_model.item(class_index, 0)
            if class_item:
                class_name = class_item.text()
                if class_name and method_name:
                    self._app_window.dwarf.breakpoint_objc(class_name + '.' + method_name)

    def _cm_refresh_methods(self):
        index = self._ObjC_classes.selectionModel().currentIndex().row()
        _class = self._ObjCclass_model.item(index, 0)
        if _class is None:
            return

        self.update_methods(_class.text())

    def _on_method_contextmenu(self, pos):
        """ Method ContextMenu
        """
        index = self._ObjC_methods.indexAt(pos).row()
        glbl_pt = self._ObjC_methods.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            context_menu.addAction(
                'Breakpoint method', lambda: self._breakpoint_method(
                    self._ObjCmethod_model.item(index, 0).text()))
            context_menu.addSeparator()

            if self._ObjC_methods.search_enabled:
                context_menu.addSeparator()
                context_menu.addAction(
                    'Search', self._ObjC_methods._on_cm_search)

        context_menu.addAction('Refresh', self._cm_refresh_methods)
        context_menu.exec_(glbl_pt)

    def _cm_refresh_classes(self):
        index = self._ObjC_modules.selectionModel().currentIndex().row()
        _module = self._ObjCmodule_model.item(index, 0)
        if _module is None:
            return

        self.update_classes(_module.text())

    def _enumerate_objc_modules(self):
        """ DwarfApiCall enumerateObjCModules
        """
        return self._app_window.dwarf.dwarf_api('enumerateObjCModules')

    def _on_module_contextmenu(self, pos):
        """ Module ContextMenu
        """
        index = self._ObjC_modules.indexAt(pos).row()
        glbl_pt = self._ObjC_modules.mapToGlobal(pos)
        context_menu = QMenu(self)

        context_menu.addAction('Refresh', self._enumerate_objc_modules)
        context_menu.exec_(glbl_pt)

    def _on_enumerate_objc_modules(self, modules):
        """ Fills the ModulesList with data
        """
        if self._ObjC_modules is None:
            return

        self._ObjC_modules.clear()
        for module in modules:
            self.add_module(module)

    def add_module(self, module):
        _module_name = QStandardItem()
        _module_name.setText(module)
        self._ObjCmodule_model.appendRow(_module_name)
