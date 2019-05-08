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
from PyQt5.QtCore import Qt, pyqtSignal, QRect
from PyQt5.QtGui import (QStandardItemModel, QIcon, QPixmap, QStandardItem,
                         QPainter, QColor, QKeySequence)
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHeaderView, QHBoxLayout,
                             QPushButton, QSpacerItem, QSizePolicy, QMenu,
                             QDialog, QLineEdit, QCheckBox, QLabel, QShortcut)

from lib import utils
from ui.list_view import DwarfListView


class AddWatcherDialog(QDialog):
    """ UserInterface for adding Memwatchers
    """

    def __init__(self, parent=None, ptr=None):
        super(AddWatcherDialog, self).__init__(parent=parent)

        self.setWindowTitle('Add Watcher')
        self.setSizeGripEnabled(False)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)
        self.setWindowFlag(Qt.MSWindowsFixedSizeDialogHint, True)

        v_box = QVBoxLayout()
        label = QLabel('Please insert a Pointer')
        v_box.addWidget(label)

        self.text_field = QLineEdit()
        self.text_field.setPlaceholderText(
            'Module.findExportByName(\'target\', \'export\') or 0x123456')
        self.text_field.setMinimumWidth(350)
        if ptr:
            self.text_field.setText(ptr)
        v_box.addWidget(self.text_field)

        self.acc_read = QCheckBox('Read')
        self.acc_read.setChecked(True)
        self.acc_write = QCheckBox('Write')
        self.acc_write.setChecked(True)
        self.acc_execute = QCheckBox('Execute')
        self.singleshot = QCheckBox('SingleShot')

        h_box = QHBoxLayout()
        h_box.addWidget(self.acc_read)
        h_box.addWidget(self.acc_write)
        h_box.addWidget(self.acc_execute)
        v_box.addLayout(h_box)
        v_box.addWidget(self.singleshot)

        h_box = QHBoxLayout()
        self._ok_button = QPushButton('OK')
        self._ok_button.clicked.connect(self.accept)
        self._cancel_button = QPushButton('Cancel')
        self._cancel_button.clicked.connect(self.close)
        h_box.addWidget(self._ok_button)
        h_box.addWidget(self._cancel_button)
        v_box.addLayout(h_box)
        self.setLayout(v_box)

    # pylint: disable=invalid-name
    def keyPressEvent(self, event):
        """ Override keyPressEvent to allow close with Enter
        """
        if event.key() == Qt.Key_Return:
            return self.accept()

        return super().keyPressEvent(event)


class WatchersPanel(QWidget):
    """ WatcherPanel

        Signals:
            onItemSelected(addr_str) - item dblclicked
            onItemAddClick

        Constants:
            MEMORY_ACCESS_READ = 1
            MEMORY_ACCESS_WRITE = 2
            MEMORY_ACCESS_EXECUTE = 4
            MEMORY_WATCH_SINGLESHOT = 8
    """
    MEMORY_ACCESS_READ = 1
    MEMORY_ACCESS_WRITE = 2
    MEMORY_ACCESS_EXECUTE = 4
    MEMORY_WATCH_SINGLESHOT = 8

    onItemDoubleClicked = pyqtSignal(int, name='onItemDoubleClicked')
    onItemAdded = pyqtSignal(int, name='onItemAdded')
    onItemRemoved = pyqtSignal(int, name='onItemRemoved')

    def __init__(self, parent=None):  # pylint: disable=too-many-statements
        super(WatchersPanel, self).__init__(parent=parent)
        self._app_window = parent

        if self._app_window.dwarf is None:
            print('Watcherpanel created before Dwarf exists')
            return

        self._uppercase_hex = True
        self.setAutoFillBackground(True)

        # connect to dwarf
        self._app_window.dwarf.onWatcherAdded.connect(self._on_watcher_added)
        self._app_window.dwarf.onWatcherRemoved.connect(
            self._on_watcher_removed)

        # setup our model
        self._watchers_model = QStandardItemModel(0, 5)
        self._watchers_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._watchers_model.setHeaderData(1, Qt.Horizontal, 'R')
        self._watchers_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                           Qt.TextAlignmentRole)
        self._watchers_model.setHeaderData(2, Qt.Horizontal, 'W')
        self._watchers_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                           Qt.TextAlignmentRole)
        self._watchers_model.setHeaderData(3, Qt.Horizontal, 'X')
        self._watchers_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                           Qt.TextAlignmentRole)
        self._watchers_model.setHeaderData(4, Qt.Horizontal, 'S')
        self._watchers_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                           Qt.TextAlignmentRole)

        # setup ui
        v_box = QVBoxLayout(self)
        v_box.setContentsMargins(0, 0, 0, 0)
        self.list_view = DwarfListView()
        self.list_view.setModel(self._watchers_model)
        self.list_view.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.list_view.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents | QHeaderView.Fixed)
        self.list_view.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents | QHeaderView.Fixed)
        self.list_view.header().setSectionResizeMode(
            3, QHeaderView.ResizeToContents | QHeaderView.Fixed)
        self.list_view.header().setSectionResizeMode(
            4, QHeaderView.ResizeToContents | QHeaderView.Fixed)
        self.list_view.header().setStretchLastSection(False)
        self.list_view.doubleClicked.connect(self._on_item_dblclick)
        self.list_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_view.customContextMenuRequested.connect(self._on_contextmenu)

        v_box.addWidget(self.list_view)
        #header = QHeaderView(Qt.Horizontal, self)

        h_box = QHBoxLayout()
        h_box.setContentsMargins(5, 2, 5, 5)
        icon = QIcon()
        icon.addPixmap(QPixmap(utils.resource_path('assets/icons/plus.svg')))
        btn1 = QPushButton(icon, '')
        btn1.setFixedSize(20, 20)
        btn1.clicked.connect(self._on_additem_clicked)
        btn2 = QPushButton(
            QIcon(QPixmap(utils.resource_path('assets/icons/dash.svg'))), '')
        btn2.setFixedSize(20, 20)
        btn2.clicked.connect(self.delete_items)
        btn3 = QPushButton(
            QIcon(QPixmap(utils.resource_path('assets/icons/trashcan.svg'))),
            '')
        btn3.setFixedSize(20, 20)
        btn3.clicked.connect(self.clear_list)
        h_box.addWidget(btn1)
        h_box.addWidget(btn2)
        h_box.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Preferred))
        h_box.addWidget(btn3)
        # header.setLayout(h_box)
        # header.setFixedHeight(25)
        # v_box.addWidget(header)
        v_box.addLayout(h_box)

        # create a centered dot icon
        _section_width = self.list_view.header().sectionSize(2)
        self._new_pixmap = QPixmap(_section_width, 20)
        self._new_pixmap.fill(Qt.transparent)
        painter = QPainter(self._new_pixmap)
        rect = QRect((_section_width * 0.5), 0, 20, 20)
        painter.setBrush(QColor('#666'))
        painter.setPen(QColor('#666'))
        painter.drawEllipse(rect)
        self._dot_icon = QIcon(self._new_pixmap)

        # shortcuts
        shortcut_add = QShortcut(
            QKeySequence(Qt.CTRL + Qt.Key_W), self._app_window,
            self._on_additem_clicked)
        shortcut_add.setAutoRepeat(False)

        self.setLayout(v_box)

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def uppercase_hex(self):
        """ Addresses displayed lower/upper-case
        """
        return self._uppercase_hex

    @uppercase_hex.setter
    def uppercase_hex(self, value):
        """ Addresses displayed lower/upper-case
            value - bool or str
                    'upper', 'lower'
        """
        if isinstance(value, bool):
            self._uppercase_hex = value
        elif isinstance(value, str):
            self._uppercase_hex = (value == 'upper')

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def do_addwatcher_dlg(self, ptr=None):  # pylint: disable=too-many-branches
        """ Shows AddWatcherDialog
        """
        watcher_dlg = AddWatcherDialog(self, ptr)
        if watcher_dlg.exec_() == QDialog.Accepted:
            mem_r = watcher_dlg.acc_read.isChecked()
            mem_w = watcher_dlg.acc_write.isChecked()
            mem_x = watcher_dlg.acc_execute.isChecked()
            mem_s = watcher_dlg.singleshot.isChecked()

            ptr = watcher_dlg.text_field.text()

            if ptr:
                if isinstance(ptr, str):
                    if ptr.startswith('0x') or ptr.startswith('#'):
                        ptr = utils.parse_ptr(ptr)
                    else:
                        try:
                            ptr = int(ptr, 10)
                        except ValueError:
                            pass

                    # int now?
                    if not isinstance(ptr, int):
                        try:
                            ptr = int(
                                self._app_window.dwarf.dwarf_api(
                                    'evaluatePtr', ptr), 16)
                        except ValueError:
                            ptr = 0

                        if ptr == 0:
                            return

                        if not self._app_window.dwarf.dwarf_api(
                                'isValidPointer', ptr):
                            return
                else:
                    return

                mem_val = 0
                if mem_r:
                    mem_val |= self.MEMORY_ACCESS_READ
                if mem_w:
                    mem_val |= self.MEMORY_ACCESS_WRITE
                if mem_x:
                    mem_val |= self.MEMORY_ACCESS_EXECUTE
                if mem_s:
                    mem_val |= self.MEMORY_WATCH_SINGLESHOT

                self.add_address(ptr, mem_val, from_api=False)

                # return [ptr, mem_val]

    def add_address(self, ptr, flags, from_api=False):
        """ Adds Address to display

            ptr - str or int
            flags - int
        """
        if isinstance(ptr, str):
            ptr = utils.parse_ptr(ptr)

        if not isinstance(flags, int):
            try:
                flags = int(flags, 10)
            except ValueError:
                flags = 3

        if not from_api:
            # function was called directly so add it to dwarf
            if not self._app_window.dwarf.is_address_watched(ptr):
                self._app_window.dwarf.dwarf_api('addWatcher', [ptr, flags])
                return

        # show header
        self.list_view.setHeaderHidden(False)

        # create items to add
        str_frmt = ''
        if self._uppercase_hex:
            str_frmt = '0x{0:X}'
        else:
            str_frmt = '0x{0:x}'

        addr = QStandardItem()
        addr.setText(str_frmt.format(ptr))

        read = QStandardItem()
        write = QStandardItem()
        execute = QStandardItem()
        singleshot = QStandardItem()

        if flags & self.MEMORY_ACCESS_READ:
            read.setIcon(self._dot_icon)
        if flags & self.MEMORY_ACCESS_WRITE:
            write.setIcon(self._dot_icon)
        if flags & self.MEMORY_ACCESS_EXECUTE:
            execute.setIcon(self._dot_icon)
        if flags & self.MEMORY_WATCH_SINGLESHOT:
            singleshot.setIcon(self._dot_icon)

        # add items as new row on top
        self._watchers_model.insertRow(
            0, [addr, read, write, execute, singleshot])

    def remove_address(self, ptr, from_api=False):
        """ Remove Address from List
        """
        if isinstance(ptr, str):
            ptr = utils.parse_ptr(ptr)

        if not from_api:
            # called somewhere so remove watcher in dwarf too
            self._app_window.dwarf.dwarf_api('removeWatcher', ptr)
            return

        str_frmt = ''
        if self._uppercase_hex:
            str_frmt = '0x{0:X}'.format(ptr)
        else:
            str_frmt = '0x{0:x}'.format(ptr)

        model = self.list_view.model()
        for item in range(model.rowCount()):
            if str_frmt == model.item(item).text():
                model.removeRow(item)

    def delete_items(self):
        """ Delete selected Items
        """
        model = self.list_view.model()

        index = self.list_view.selectionModel().currentIndex().row()
        if index != -1:
            ptr = model.item(index, 0).text()
            self.remove_address(ptr)

    def clear_list(self):
        """ Clear the List
        """
        model = self.list_view.model()

        # go through all items and tell it gets removed
        for item in range(model.rowCount()):
            ptr = model.item(item, 0).text()
            self.remove_address(ptr)

        if model.rowCount() > 0:
            # something was wrong it should be empty
            model.removeRows(0, model.rowCount())

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_contextmenu(self, pos):
        index = self.list_view.indexAt(pos).row()
        if index != -1:
            glbl_pt = self.list_view.mapToGlobal(pos)
            context_menu = QMenu(self)
            context_menu.addAction(
                'Copy Address', lambda: utils.copy_hex_to_clipboard(
                    self._watchers_model.item(index, 0).text()))
            context_menu.addAction(
                'Delete Address', lambda: self.remove_address(
                    self._watchers_model.item(index, 0).text()))
            context_menu.exec_(glbl_pt)

    def _on_item_dblclick(self, model_index):
        row = self._watchers_model.itemFromIndex(model_index).row()
        if row != -1:
            ptr = self._watchers_model.item(row, 0).text()
            self.onItemDoubleClicked.emit(ptr)

    def _on_additem_clicked(self):
        if self._app_window.dwarf.pid == 0:
            return

        self.do_addwatcher_dlg()

    def _on_watcher_added(self, ptr, flags):
        """ Callback from Dwarf after Watcher is added
        """
        ptr = utils.parse_ptr(ptr)
        # add to watcherslist
        self.add_address(ptr, flags, from_api=True)
        self.onItemAdded.emit(ptr)

    def _on_watcher_removed(self, ptr):
        """ Callback from Dwarf after watcher is removed
        """
        ptr = utils.parse_ptr(ptr)
        # remove from list
        self.remove_address(ptr, from_api=True)
        self.onItemRemoved.emit(ptr)
