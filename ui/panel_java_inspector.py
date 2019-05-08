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
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QHeaderView, QHBoxLayout, QMenu

from ui.list_view import DwarfListView


class JavaInspector(QWidget):
    """ Java Class/Methods Lists
    """

    def __init__(self, parent=None):
        super(JavaInspector, self).__init__(parent)

        self._app_window = parent

        self._app_window.dwarf.onEnumerateJavaMethodsComplete.connect(
            self._on_method_enumeration_complete)
        self._app_window.dwarf.onEnumerateJavaClassesStart.connect(
            self._on_class_enumeration_start)
        self._app_window.dwarf.onEnumerateJavaClassesMatch.connect(
            self._on_class_enumeration_match)
        self._app_window.dwarf.onEnumerateJavaClassesComplete.connect(
            self._on_class_enumeration_complete)

        self._java_classes = DwarfListView(self)
        self._javaclass_model = QStandardItemModel(0, 1)
        self._javaclass_model.setHeaderData(0, Qt.Horizontal, 'Class')
        self._java_classes.setModel(self._javaclass_model)
        self._java_classes.selectionModel().selectionChanged.connect(
            self._class_clicked)
        self._java_classes.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._java_classes.setContextMenuPolicy(Qt.CustomContextMenu)
        self._java_classes.customContextMenuRequested.connect(
            self._on_class_contextmenu)
        self._java_classes.doubleClicked.connect(self._class_dblclicked)

        self._java_methods = DwarfListView(self)
        self._javamethod_model = QStandardItemModel(0, 1)
        self._javamethod_model.setHeaderData(0, Qt.Horizontal, 'Method')
        self._java_methods.setModel(self._javamethod_model)
        self._java_methods.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._java_methods.setContextMenuPolicy(Qt.CustomContextMenu)
        self._java_methods.customContextMenuRequested.connect(
            self._on_method_contextmenu)
        self._java_methods.doubleClicked.connect(self._method_dblclicked)

        h_box = QHBoxLayout()
        h_box.setContentsMargins(0, 0, 0, 0)
        h_box.addWidget(self._java_classes)
        h_box.addWidget(self._java_methods)
        self.setLayout(h_box)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def update_classes(self):
        """ Refresh Classeslist
        """
        self._app_window.dwarf.dwarf_api('enumerateJavaClasses')

    def update_methods(self, class_name):
        """ Refresh Methodslist
        """
        if class_name:
            self._app_window.dwarf.dwarf_api('enumerateJavaMethods',
                                             class_name)

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _class_clicked(self):
        index = self._java_classes.selectionModel().currentIndex().row()
        _class = self._javaclass_model.item(index, 0)
        if _class is None:
            return

        self._app_window.dwarf.dwarf_api('enumerateJavaMethods', _class.text())

    def _on_class_enumeration_start(self):
        self._java_classes.clear()

    def _on_class_enumeration_match(self, java_class):
        _class_name = QStandardItem()
        _class_name.setText(java_class)
        self._javaclass_model.appendRow(_class_name)

    def _on_class_enumeration_complete(self):
        self._java_classes.sortByColumn(0, 0)

    def _on_method_enumeration_complete(self, data):
        self._java_methods.clear()
        _class, methods = data
        for method in methods:
            _method_name = QStandardItem()
            _method_name.setText(method)
            self._javamethod_model.appendRow(_method_name)

    def _class_dblclicked(self):
        """ Class DoubleClicked
        """
        index = self._java_classes.selectionModel().currentIndex().row()
        if index:
            class_item = self._javaclass_model.item(index, 0)
            if class_item:
                class_name = class_item.text()
                if class_name:
                    self._hook_class(class_name)

    def _method_dblclicked(self):
        """ Function DoubleClicked
        """
        class_index = self._java_classes.selectionModel().currentIndex().row()
        method_index = self._java_methods.selectionModel().currentIndex().row()
        if class_index and method_index:
            class_item = self._javaclass_model.item(class_index, 0)
            method_item = self._javamethod_model.item(method_index, 0)
            if class_item and method_item:
                class_name = class_item.text()
                method_name = method_item.text()
                if class_name and method_name:
                    self._app_window.dwarf.hook_java(class_name + '.'
                                                     + method_name)

    def _hook_class(self, class_name):
        if class_name:
            self._app_window.dwarf.hook_java(class_name)

    def _hook_class_functions(self, class_name):
        if class_name:
            self._app_window.dwarf.dwarf_api('hookAllJavaMethods', class_name)

    def _on_class_contextmenu(self, pos):
        """ Modules ContextMenu
        """
        index = self._java_classes.indexAt(pos).row()
        glbl_pt = self._java_classes.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            context_menu.addAction(
                'Hook constructor', lambda: self._hook_class(
                    self._javaclass_model.item(index, 0).text()))
            context_menu.addAction(
                'Hook all methods', lambda: self._hook_class_functions(
                    self._javaclass_model.item(index, 0).text()))
            context_menu.addSeparator()

        context_menu.addAction('Refresh', self.update_classes)
        context_menu.exec_(glbl_pt)

    def _hook_method(self, method_name):
        class_index = self._java_classes.selectionModel().currentIndex().row()
        if class_index:
            class_item = self._javaclass_model.item(class_index, 0)
            if class_item:
                class_name = class_item.text()
                if class_name and method_name:
                    self._app_window.dwarf.hook_java(class_name + '.'
                                                     + method_name)

    def _cm_refresh_methods(self):
        index = self._java_classes.selectionModel().currentIndex().row()
        _class = self._javaclass_model.item(index, 0)
        if _class is None:
            return

        self.update_methods(_class.text())

    def _on_method_contextmenu(self, pos):
        """ Modules ContextMenu
        """
        index = self._java_methods.indexAt(pos).row()
        glbl_pt = self._java_methods.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            context_menu.addAction(
                'Hook method', lambda: self._hook_method(
                    self._javamethod_model.item(index, 0).text()))
            context_menu.addSeparator()

        context_menu.addAction('Refresh', self._cm_refresh_methods)
        context_menu.exec_(glbl_pt)
