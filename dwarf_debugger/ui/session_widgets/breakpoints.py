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
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import (QStandardItemModel, QStandardItem, QIcon, QFont, QKeySequence, QCursor)
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QHeaderView,
                             QPushButton, QSizePolicy, QSpacerItem, QShortcut, QMenu)
from dwarf_debugger.ui.dialogs.dialog_input_multiline import InputMultilineDialog

from dwarf_debugger.ui.widgets.list_view import DwarfListView
from dwarf_debugger.ui.dialogs.dialog_input import InputDialog

from dwarf_debugger.lib import utils
from dwarf_debugger.lib.types.breakpoint import BREAKPOINT_NATIVE, BREAKPOINT_JAVA, BREAKPOINT_INITIALIZATION, BREAKPOINT_OBJC


class BreakpointsWidget(QWidget):
    """ BreakpointsWidget

        Signals:
            onBreakpointChanged(str) - ptr
            onBreakpointRemoved(str) - ptr
    """

    onBreakpointChanged = pyqtSignal(str, name='onBreakpointChanged')
    onBreakpointsRemoved = pyqtSignal(str, name='onBreakpointRemoved')

    def __init__(self, parent=None):  # pylint: disable=too-many-statements
        super(BreakpointsWidget, self).__init__(parent=parent)

        self._app_window = parent

        if self._app_window.dwarf is None:
            print('BreakpointsWidget created before Dwarf exists')
            return

        # connect to dwarf
        self._app_window.dwarf.onApplyContext.connect(self._on_apply_context)
        self._app_window.dwarf.onAddJavaBreakpoint.connect(self._on_add_breakpoint)
        self._app_window.dwarf.onAddObjCBreakpoint.connect(self._on_add_breakpoint)
        self._app_window.dwarf.onAddNativeBreakpoint.connect(self._on_add_breakpoint)
        self._app_window.dwarf.onAddModuleInitializationBreakpoint.connect(self._on_add_breakpoint)
        self._app_window.dwarf.onAddJavaClassInitializationBreakpoint.connect(self._on_add_breakpoint)
        self._app_window.dwarf.onHitModuleInitializationBreakpoint.connect(
            self._on_hit_module_initialization_breakpoint)
        self._app_window.dwarf.onHitJavaClassInitializationBreakpoint.connect(
            self._on_hit_java_class_initialization_breakpoint)
        self._app_window.dwarf.onDeleteBreakpoint.connect(self._on_breakpoint_deleted)

        self._breakpoints_list = DwarfListView()
        self._breakpoints_list.doubleClicked.connect(self._on_double_clicked)
        self._breakpoints_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._breakpoints_list.customContextMenuRequested.connect(
            self._on_context_menu)
        self._breakpoints_model = QStandardItemModel(0, 3)

        self._breakpoints_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._breakpoints_model.setHeaderData(1, Qt.Horizontal, 'T')
        self._breakpoints_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._breakpoints_model.setHeaderData(2, Qt.Horizontal, '<>')
        self._breakpoints_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)

        self._breakpoints_list.setModel(self._breakpoints_model)

        self._breakpoints_list.header().setStretchLastSection(False)
        self._breakpoints_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents | QHeaderView.Interactive)
        self._breakpoints_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self._breakpoints_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)

        v_box = QVBoxLayout(self)
        v_box.setContentsMargins(0, 0, 0, 0)
        v_box.addWidget(self._breakpoints_list)

        h_box = QHBoxLayout()
        h_box.setContentsMargins(5, 2, 5, 5)
        self.btn1 = QPushButton(
            QIcon(utils.resource_path('assets/icons/plus.svg')), '')
        self.btn1.setFixedSize(20, 20)
        self.btn1.clicked.connect(self._on_add_item_clicked)
        btn2 = QPushButton(
            QIcon(utils.resource_path('assets/icons/dash.svg')), '')
        btn2.setFixedSize(20, 20)
        btn2.clicked.connect(self.delete_items)
        btn3 = QPushButton(
            QIcon(utils.resource_path('assets/icons/trashcan.svg')), '')
        btn3.setFixedSize(20, 20)
        btn3.clicked.connect(self.clear_list)
        h_box.addWidget(self.btn1)
        h_box.addWidget(btn2)
        h_box.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Preferred))
        h_box.addWidget(btn3)
        # header.setLayout(h_box)
        # header.setFixedHeight(25)
        # v_box.addWidget(header)
        v_box.addLayout(h_box)
        self.setLayout(v_box)

        self._bold_font = QFont(self._breakpoints_list.font())
        self._bold_font.setBold(True)

        shortcut_addnative = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_N), self._app_window,
            self._on_add_native_breakpoint)
        shortcut_addnative.setAutoRepeat(False)

        shortcut_addjava = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_J), self._app_window,
            self._on_add_java_breakpoint)
        shortcut_addjava.setAutoRepeat(False)

        shortcut_add_native_onload = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_O), self._app_window,
            self._on_add_module_initialization_breakpoint)
        shortcut_add_native_onload.setAutoRepeat(False)

        # new menu
        self.new_menu = QMenu('New')
        self.new_menu.addAction('Native', self._on_add_native_breakpoint)
        self.new_menu.addAction('Module initialization', self._on_add_module_initialization_breakpoint)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def delete_items(self):
        """ Delete selected Items
        """
        index = self._breakpoints_list.selectionModel().currentIndex().row()
        if index != -1:
            self._on_delete_breakpoint(index)
            self._breakpoints_model.removeRow(index)

    def clear_list(self):
        """ Clear the List
        """
        # go through all items and tell it gets removed
        for item in range(self._breakpoints_model.rowCount()):
            self._on_delete_breakpoint(item)

        if self._breakpoints_model.rowCount() > 0:
            # something was wrong it should be empty
            self._breakpoints_model.removeRows(0, self._breakpoints_model.rowCount())

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_apply_context(self, context):
        if context['reason'] == -1:
            if self._app_window.dwarf.java_available:
                self.new_menu.addAction('Java', self._on_add_java_breakpoint)
                self.new_menu.addAction('Java class initialization', self._on_add_java_class_initialization_breakpoint)

    def _on_add_breakpoint(self, breakpoint):
        type_ = QStandardItem()
        type_.setFont(self._bold_font)
        type_.setTextAlignment(Qt.AlignCenter)
        if breakpoint.breakpoint_type == BREAKPOINT_NATIVE:
            type_.setText('N')
            type_.setToolTip('Native breakpoint')
        elif breakpoint.breakpoint_type == BREAKPOINT_JAVA:
            type_.setText('J')
            type_.setToolTip('Java breakpoint')
        elif breakpoint.breakpoint_type == BREAKPOINT_INITIALIZATION:
            type_.setText('C')
            type_.setToolTip('Initialization breakpoint')
        elif breakpoint.breakpoint_type == BREAKPOINT_OBJC:
            type_.setText('O')
            type_.setToolTip('ObjC breakpoint')
        else:
            type_.setText('U')
            type_.setToolTip('Unknown Type')

        addr = QStandardItem()

        if breakpoint.breakpoint_type == BREAKPOINT_JAVA :
            addr.setText(breakpoint.get_target())
        elif breakpoint.breakpoint_type == BREAKPOINT_OBJC :
            addr.setText(breakpoint.get_target())
        elif breakpoint.breakpoint_type == BREAKPOINT_INITIALIZATION:
            addr.setText(breakpoint.get_target())
            addr.setData(breakpoint.debug_symbol, Qt.UserRole + 2)
        else:
            str_fmt = '0x{0:x}'
            if self._breakpoints_list.uppercase_hex:
                str_fmt = '0x{0:X}'
            # addr.setTextAlignment(Qt.AlignCenter)
            addr.setText(str_fmt.format(breakpoint.get_target()))

        condition = QStandardItem()
        condition.setTextAlignment(Qt.AlignCenter)
        condition.setFont(self._bold_font)
        if breakpoint.condition and breakpoint.condition != 'null' and breakpoint.condition != 'undefined':
            condition.setText('ƒ')
            condition.setToolTip(breakpoint.condition)
            condition.setData(breakpoint.condition, Qt.UserRole + 2)

        self._breakpoints_model.appendRow([addr, type_, condition])
        self._breakpoints_list.resizeColumnToContents(0)

    def _on_hit_module_initialization_breakpoint(self, data):
        items = self._breakpoints_model.findItems(data[1]['module'], Qt.MatchExactly, 2)
        if len(items) > 0:
            self._breakpoints_model.item(items[0].row(), 0).setText(data[1]['moduleBase'])

    def _on_hit_java_class_initialization_breakpoint(self, data):
        items = self._breakpoints_model.findItems(data[0], Qt.MatchExactly, 2)
        if len(items) > 0:
            pass

    def _on_double_clicked(self, model_index):
        item = self._breakpoints_model.itemFromIndex(model_index)
        if model_index.column() == 2 and item.text() == 'ƒ':
            self._on_modify_condition(model_index.row())
        else:
            self._app_window.jump_to_address(self._breakpoints_model.item(model_index.row(), 0).text(), view=1)

    def _on_context_menu(self, pos):
        context_menu = QMenu(self)
        context_menu.addMenu(self.new_menu)

        context_menu.addSeparator()
        index = self._breakpoints_list.indexAt(pos).row()
        if index != -1:
            context_menu.addAction(
                'Copy address', lambda: utils.copy_hex_to_clipboard(
                    self._breakpoints_model.item(index, 0).text()))
            context_menu.addAction(
                'Jump to address', lambda: self._app_window.jump_to_address(
                    self._breakpoints_model.item(index, 0).text()))
            context_menu.addSeparator()
            context_menu.addAction('Edit Condition', lambda: self._on_modify_condition(index))
            context_menu.addSeparator()
            context_menu.addAction('Delete Breakpoint', lambda: self._on_delete_breakpoint(index))

            if self._breakpoints_list.search_enabled:
                context_menu.addSeparator()
                context_menu.addAction(
                    'Search', self._breakpoints_list._on_cm_search)

        # show context menu
        global_pt = self._breakpoints_list.mapToGlobal(pos)
        context_menu.exec(global_pt)

    def _on_modify_condition(self, num_row):
        item = self._breakpoints_model.item(num_row, 2)
        data = item.data(Qt.UserRole + 2)
        if data is None:
            data = ''
        ptr = self._breakpoints_model.item(num_row, 0).text()
        accept, input_ = InputMultilineDialog().input(
            'Condition for breakpoint %s' % ptr, input_content=data)
        if accept:
            what = utils.parse_ptr(ptr)
            if what == 0:
                what = self._breakpoints_model.item(num_row, 2).data(Qt.UserRole + 2)
            if self._app_window.dwarf.dwarf_api('setBreakpointCondition', [what, input_.replace('\n', '')]):
                item.setData(input_, Qt.UserRole + 2)
                if not item.text():
                    item.setText('ƒ')
                item.setToolTip(input_)
                self.onBreakpointChanged.emit(ptr)

    # + button
    def _on_add_item_clicked(self):
        self.new_menu.exec_(QCursor.pos())

    # shortcuts/menu
    def _on_add_native_breakpoint(self):
        self._app_window.dwarf.breakpoint_native()

    def _on_add_java_breakpoint(self):
        self._app_window.dwarf.breakpoint_java()

    def _on_add_module_initialization_breakpoint(self):
        self._app_window.dwarf.breakpoint_module_initialization()

    def _on_add_java_class_initialization_breakpoint(self):
        self._app_window.dwarf.breakpoint_java_class_initialization()

    def _on_delete_breakpoint(self, num_row):
        breakpoint_type = self._breakpoints_model.item(num_row, 1).text()
        if breakpoint_type == 'N':
            ptr = self._breakpoints_model.item(num_row, 0).text()
            ptr = utils.parse_ptr(ptr)
            self._app_window.dwarf.dwarf_api('removeBreakpoint', ptr)
            self.onBreakpointRemoved.emit(str(ptr))
        elif breakpoint_type == 'J':
            target = self._breakpoints_model.item(num_row, 0).text()
            self._app_window.dwarf.dwarf_api('removeBreakpoint', target)
        elif breakpoint_type == 'O':
            target = self._breakpoints_model.item(num_row, 0).text()
            self._app_window.dwarf.dwarf_api('removeBreakpoint', target)
        elif breakpoint_type == 'C':
            item = self._breakpoints_model.item(num_row, 0)
            target = item.text()
            is_native = item.data(Qt.UserRole + 2) is None
            if is_native:
                self._app_window.dwarf.dwarf_api('removeModuleInitializationBreakpoint', target)
            else:
                self._app_window.dwarf.dwarf_api('removeJavaClassInitializationBreakpoint', target)
        elif breakpoint_type == 'U':
            ptr = self._breakpoints_model.item(num_row, 0).text()
            ptr = utils.parse_ptr(ptr)
            self._app_window.dwarf.dwarf_api('removeBreakpoint', ptr)
            self.onBreakpointRemoved.emit(str(ptr))

    def _on_breakpoint_deleted(self, parts):
        _msg, _type, _val = parts

        additional = None

        if _type == 'objc' or _type == 'java' or _type == 'java_class_initialization':
            str_frmt = _val
            item_index = 0
        elif _type == 'module_initialization':
            str_frmt = _val
            item_index = 0
        else:
            _ptr = utils.parse_ptr(_val)
            if self._breakpoints_list._uppercase_hex:
                str_frmt = '0x{0:X}'.format(_ptr)
            else:
                str_frmt = '0x{0:x}'.format(_ptr)
            item_index = 0

        for _item in range(self._breakpoints_model.rowCount()):
            item = self._breakpoints_model.item(_item, item_index)

            if item is None:
                continue

            if str_frmt == item.text():
                if additional is not None:
                    if additional == self._breakpoints_model.item(_item, 2).text():
                        self._breakpoints_model.removeRow(_item)
                else:
                    self._breakpoints_model.removeRow(_item)
