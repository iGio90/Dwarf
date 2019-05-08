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
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import (QStandardItemModel, QStandardItem, QIcon, QPixmap,
                         QFont, QKeySequence, QCursor)
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QHeaderView,
                             QPushButton, QSizePolicy, QSpacerItem, QShortcut,
                             QMenu)

from ui.list_view import DwarfListView
from ui.dialog_input import InputDialog
from ui.dialog_input_multiline import InputMultilineDialog

from lib import utils
from lib.hook import Hook


class HooksPanel(QWidget):
    """ HooksPanel

        Signals:
            onShowMemoryRequest(str) - ptr
            onHookChanged(str) - ptr
            onHookRemoved(str) - ptr
    """

    onShowMemoryRequest = pyqtSignal(str, name='onShowMemoryRequest')
    onHookChanged = pyqtSignal(str, name='onHookChanged')
    onHookRemoved = pyqtSignal(str, name='onHookRemoved')

    def __init__(self, parent=None):  # pylint: disable=too-many-statements
        super(HooksPanel, self).__init__(parent=parent)

        self._app_window = parent

        if self._app_window.dwarf is None:
            print('HooksPanel created before Dwarf exists')
            return

        # connect to dwarf
        self._app_window.dwarf.onAddJavaHook.connect(self._on_add_hook)
        self._app_window.dwarf.onAddNativeHook.connect(self._on_add_hook)
        self._app_window.dwarf.onAddOnLoadHook.connect(self._on_add_hook)
        self._app_window.dwarf.onHitOnLoad.connect(self._on_hit_onload)

        self._hooks_list = DwarfListView()
        self._hooks_list.doubleClicked.connect(self._on_dblclicked)
        self._hooks_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._hooks_list.customContextMenuRequested.connect(
            self._on_contextmenu)
        self._hooks_model = QStandardItemModel(0, 5)

        self._hooks_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._hooks_model.setHeaderData(1, Qt.Horizontal, 'T')
        self._hooks_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                        Qt.TextAlignmentRole)
        self._hooks_model.setHeaderData(2, Qt.Horizontal, 'Input')
        self._hooks_model.setHeaderData(3, Qt.Horizontal, '{}')
        self._hooks_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                        Qt.TextAlignmentRole)
        self._hooks_model.setHeaderData(4, Qt.Horizontal, '<>')
        self._hooks_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                        Qt.TextAlignmentRole)

        self._hooks_list.setModel(self._hooks_model)

        self._hooks_list.header().setStretchLastSection(False)
        self._hooks_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents | QHeaderView.Interactive)
        self._hooks_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self._hooks_list.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self._hooks_list.header().setSectionResizeMode(
            3, QHeaderView.ResizeToContents)
        self._hooks_list.header().setSectionResizeMode(
            4, QHeaderView.ResizeToContents)

        v_box = QVBoxLayout(self)
        v_box.setContentsMargins(0, 0, 0, 0)
        v_box.addWidget(self._hooks_list)
        #header = QHeaderView(Qt.Horizontal, self)

        h_box = QHBoxLayout()
        h_box.setContentsMargins(5, 2, 5, 5)
        icon = QIcon()
        icon.addPixmap(QPixmap(utils.resource_path('assets/icons/plus.svg')))
        self.btn1 = QPushButton(icon, '')
        self.btn1.setFixedSize(20, 20)
        self.btn1.clicked.connect(self._on_additem_clicked)
        btn2 = QPushButton(
            QIcon(QPixmap(utils.resource_path('assets/icons/dash.svg'))), '')
        btn2.setFixedSize(20, 20)
        btn2.clicked.connect(self.delete_items)
        btn3 = QPushButton(
            QIcon(QPixmap(utils.resource_path('assets/icons/trashcan.svg'))),
            '')
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

        self._bold_font = QFont(self._hooks_list.font())
        self._bold_font.setBold(True)

        shortcut_addnative = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_N), self._app_window,
            self._on_addnative)
        shortcut_addnative.setAutoRepeat(False)

        shortcut_addjava = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_J), self._app_window,
            self._on_addjava)
        shortcut_addjava.setAutoRepeat(False)

        shortcut_addonload = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_O), self._app_window,
            self._on_addonload)
        shortcut_addonload.setAutoRepeat(False)

        # new menu
        self.new_menu = QMenu('New')
        self.new_menu.addAction('Native', self._on_addnative)
        self.new_menu.addAction('Java', self._on_addjava)
        self.new_menu.addAction('Module loading', self._on_addonload)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def delete_items(self):
        """ Delete selected Items
        """
        index = self._hooks_list.selectionModel().currentIndex().row()
        if index != -1:
            self._on_deletehook(index)
            self._hooks_model.removeRow(index)

    def clear_list(self):
        """ Clear the List
        """
        # go through all items and tell it gets removed
        for item in range(self._hooks_model.rowCount()):
            if item:
                self._on_deletehook(item)

        if self._hooks_model.rowCount() > 0:
            # something was wrong it should be empty
            self._hooks_model.removeRows(0, self._hooks_model.rowCount())

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_add_hook(self, hook):
        type_ = QStandardItem()
        type_.setFont(self._bold_font)
        type_.setTextAlignment(Qt.AlignCenter)
        if hook.hook_type == Hook.HOOK_NATIVE:
            type_.setText('N')
            type_.setToolTip('Native Hook')
        elif hook.hook_type == Hook.HOOK_JAVA:
            type_.setText('J')
            type_.setToolTip('Java Hook')
        elif hook.hook_type == Hook.HOOK_ONLOAD:
            type_.setText('O')
            type_.setToolTip('OnLoad Hook')
        else:
            type_.setText('U')
            type_.setToolTip('Unknown Type')

        addr = QStandardItem()

        if hook.hook_type == Hook.HOOK_JAVA:
            parts = hook.get_input().split('.')
            addr.setText('.'.join(parts[:len(parts) - 1]))
        else:
            str_fmt = '0x{0:x}'
            if self._hooks_list.uppercase_hex:
                str_fmt = '0x{0:X}'
            # addr.setTextAlignment(Qt.AlignCenter)
            addr.setText(str_fmt.format(hook.get_ptr()))

        inp = QStandardItem()
        inp_text = hook.get_input()
        if hook.hook_type == Hook.HOOK_JAVA:
            parts = inp_text.split('.')
            inp_text = parts[len(parts) - 1]
        # if len(inp_text) > 15:
        #    inp_text = inp_text[:15] + '...'
        #    inp.setToolTip(hook.get_input())
        inp.setText(inp_text)
        inp.setData(hook.get_input(), Qt.UserRole + 2)
        inp.setToolTip(hook.get_input())

        logic = QStandardItem()
        logic.setTextAlignment(Qt.AlignCenter)
        logic.setFont(self._bold_font)
        if hook.logic and hook.logic != 'null' and hook.logic != 'undefined':
            logic.setText('ƒ')
            logic.setToolTip(hook.logic)
            logic.setData(hook.logic, Qt.UserRole + 2)

        condition = QStandardItem()
        condition.setTextAlignment(Qt.AlignCenter)
        condition.setFont(self._bold_font)
        if hook.condition and hook.condition != 'null' and hook.condition != 'undefined':
            condition.setText('ƒ')
            condition.setToolTip(hook.condition)
            condition.setData(hook.condition, Qt.UserRole + 2)

        self._hooks_model.appendRow([addr, type_, inp, logic, condition])

    def _on_hit_onload(self, data):
        items = self._hooks_model.findItems(data[0], Qt.MatchExactly, 2)
        if len(items) > 0:
            self._hooks_model.item(items[0].row(), 0).setText(data[1])

    def _on_dblclicked(self, model_index):
        item = self._hooks_model.itemFromIndex(model_index)
        if model_index.column() == 3 and item.text() == 'ƒ':
            self._on_modify_logic(model_index.row())
        elif model_index.column() == 4 and item.text() == 'ƒ':
            self._on_modify_condition(model_index.row())
        else:
            self.onShowMemoryRequest.emit(
                self._hooks_model.item(model_index.row(), 0).text())

    def _on_contextmenu(self, pos):
        context_menu = QMenu(self)
        context_menu.addMenu(self.new_menu)
        context_menu.addSeparator()
        index = self._hooks_list.indexAt(pos).row()
        if index != -1:
            context_menu.addAction(
                'Copy Address', lambda: utils.copy_hex_to_clipboard(
                    self._hooks_model.item(index, 0).text()))
            context_menu.addSeparator()
            context_menu.addAction(
                'Modify Logic', lambda: self._on_modify_logic(index))
            context_menu.addAction(
                'Modify Condition', lambda: self._on_modify_condition(index))
            context_menu.addSeparator()
            context_menu.addAction(
                'Delete Hook', lambda: self._on_deletehook(index))
        global_pt = self._hooks_list.mapToGlobal(pos)
        context_menu.exec(global_pt)

    def _on_modify_logic(self, num_row):
        item = self._hooks_model.item(num_row, 3)
        data = item.data(Qt.UserRole + 2)
        if data is None:
            data = ''
        accept, input_ = InputMultilineDialog().input(
            'insert logic', input_content=data)
        if accept:
            ptr = self._hooks_model.item(num_row, 0).text()
            what = utils.parse_ptr(ptr)
            if what == 0:
                what = self._hooks_model.item(num_row, 2).data(Qt.UserRole + 2)
            if self.app.dwarf.dwarf_api('setHookLogic', [what, input_]):
                item.setData(input_, Qt.UserRole + 2)
                if not item.text():
                    item.setText('ƒ')
                item.setToolTip(input_)
                self.onHookChanged.emit(ptr)

    def _on_modify_condition(self, num_row):
        item = self._hooks_model.item(num_row, 4)
        data = item.data(Qt.UserRole + 2)
        if data is None:
            data = ''
        accept, input_ = InputDialog().input(
            self._app_window, 'insert condition', input_content=data)
        if accept:
            ptr = self._hooks_model.item(num_row, 0).text()
            what = utils.parse_ptr(ptr)
            if what == 0:
                what = self._hooks_model.item(num_row, 2).data(Qt.UserRole + 2)
            if self._app_window.dwarf.dwarf_api('setHookCondition',
                                                [what, input_]):
                item.setData(input_, Qt.UserRole + 2)
                if not item.text():
                    item.setText('ƒ')
                item.setToolTip(input_)
                self.onHookChanged.emit(ptr)

    # + button
    def _on_additem_clicked(self):
        self.new_menu.exec_(QCursor.pos())

    # shortcuts/menu
    def _on_addnative(self):
        self._app_window.dwarf.hook_native()

    def _on_addjava(self):
        self._app_window.dwarf.hook_java()

    def _on_addonload(self):
        self._app_window.dwarf.hook_onload()

    def _on_deletehook(self, num_row):
        hook_type = self._hooks_model.item(num_row, 1).text()
        if hook_type == 'N':
            ptr = self._hooks_model.item(num_row, 0).text()
            ptr = utils.parse_ptr(ptr)
            self._app_window.dwarf.dwarf_api('deleteHook', ptr)
            self.onHookRemoved.emit(str(ptr))
        elif hook_type == 'J':
            input_ = self._hooks_model.item(num_row, 2).data(Qt.UserRole + 2)
            self._app_window.dwarf.dwarf_api('deleteHook', input_)
        elif hook_type == 'O':
            input_ = self._hooks_model.item(num_row, 2).data(Qt.UserRole + 2)
            self._app_window.dwarf.dwarf_api('deleteHook', input_)
        elif hook_type == 'U':
            ptr = self._hooks_model.item(num_row, 0).text()
            ptr = utils.parse_ptr(ptr)
            self._app_window.dwarf.dwarf_api('deleteHook', ptr)
            self.onHookRemoved.emit(str(ptr))
