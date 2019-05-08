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
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QHeaderView, QMenu

from ui.list_view import DwarfListView

from lib import utils


class RangesPanel(DwarfListView):
    """ RangesPanel

        Signals:
            onItemDoubleClicked(str) - only fired when prot has +r
            onDumpBinary([ptr, size#int]) - MenuItem DumpBinary
            onAddWatcher(str) - MenuItem AddWatcher
    """

    onItemDoubleClicked = pyqtSignal(str, name='onItemDoubleClicked')
    onDumpBinary = pyqtSignal(list, name='onDumpBinary')
    onAddWatcher = pyqtSignal(str, name='onAddWatcher')

    def __init__(self, parent=None):
        super(RangesPanel, self).__init__(parent=parent)
        self._app_window = parent

        if self._app_window.dwarf is None:
            print('RangesPanel created before Dwarf exists')
            return

        # connect to dwarf
        self._app_window.dwarf.onSetRanges.connect(self.set_ranges)

        self._uppercase_hex = True

        self._ranges_model = QStandardItemModel(0, 6)
        self._ranges_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._ranges_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(1, Qt.Horizontal, 'Size')
        self._ranges_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(2, Qt.Horizontal, 'Protection')
        self._ranges_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(3, Qt.Horizontal, 'FileOffset')
        self._ranges_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(4, Qt.Horizontal, 'FileSize')
        self._ranges_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(5, Qt.Horizontal, 'FilePath')

        self.setHeaderHidden(False)
        self.setAutoFillBackground(True)
        self.setEditTriggers(self.NoEditTriggers)
        self.setRootIsDecorated(False)
        self.doubleClicked.connect(self._range_dblclicked)
        self.setModel(self._ranges_model)
        # self.setSortingEnabled(True)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_contextmenu)

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
    def set_ranges(self, ranges):
        """ Fills Rangelist with Data
        """
        if isinstance(ranges, list):
            self._ranges_model.removeRows(0, self._ranges_model.rowCount())
            for range_entry in ranges:
                # create items to add
                str_frmt = ''
                if self._uppercase_hex:
                    str_frmt = '0x{0:X}'
                else:
                    str_frmt = '0x{0:x}'

                addr = QStandardItem()
                addr.setTextAlignment(Qt.AlignCenter)
                addr.setText(str_frmt.format(int(range_entry['base'], 16)))

                size = QStandardItem()
                size.setTextAlignment(Qt.AlignRight)
                size.setText("{0:,d}".format(int(range_entry['size'])))

                protection = QStandardItem()
                protection.setTextAlignment(Qt.AlignCenter)
                protection.setText(range_entry['protection'])

                file_path = None
                file_addr = None
                file_size = None

                if len(range_entry) > 3:
                    if range_entry['file']['path']:
                        file_path = QStandardItem()
                        file_path.setText(range_entry['file']['path'])

                    if range_entry['file']['offset']:
                        file_addr = QStandardItem()
                        file_addr.setTextAlignment(Qt.AlignCenter)
                        file_addr.setText(
                            str_frmt.format(range_entry['file']['offset']))

                    if range_entry['file']['size']:
                        file_size = QStandardItem()
                        file_size.setTextAlignment(Qt.AlignRight)
                        file_size.setText("{0:,d}".format(
                            int(range_entry['file']['size'])))

                self._ranges_model.appendRow(
                    [addr, size, protection, file_addr, file_size, file_path])

    def update_ranges(self):
        """ DwarfApiCall updateRanges
        """
        self._app_window.dwarf.dwarf_api('updateRanges')

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_contextmenu(self, pos):
        """ ContextMenu
        """
        index = self.indexAt(pos).row()
        glbl_pt = self.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            mem_prot = self._ranges_model.item(index, 2).text()
            # is readable
            if 'r' in mem_prot:
                context_menu.addAction(
                    'Dump Binary', lambda: self._on_dumprange(
                        self._ranges_model.item(index, 0).text(),
                        self._ranges_model.item(index, 1).text()))
                context_menu.addSeparator()

            context_menu.addAction(
                'Add Watcher', lambda: self._on_addwatcher(
                    self._ranges_model.item(index, 0).text()))

            context_menu.addAction(
                'Copy Address', lambda: utils.copy_hex_to_clipboard(
                    self._ranges_model.item(index, 0).text()))
            context_menu.addSeparator()

        context_menu.addAction('Refresh', self.update_ranges)
        context_menu.exec_(glbl_pt)

    def _range_dblclicked(self, model_index):
        """ RangeItem DoubleClicked
        """
        row = self._ranges_model.itemFromIndex(model_index).row()
        if row != -1:
            mem_prot = self._ranges_model.item(row, 2).text()
            # not readable?
            if 'r' in mem_prot:
                ptr = self._ranges_model.item(row, 0).text()
                self.onItemDoubleClicked.emit(ptr)

    def _on_dumprange(self, ptr, size):
        """ MenuItem DumpBinary
        """
        if isinstance(ptr, int):
            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'
            ptr = str_fmt.format(ptr)

        size = size.replace(',', '')
        self.onDumpBinary.emit([ptr, size])

    def _on_addwatcher(self, ptr):
        """ MenuItem AddWatcher
        """
        if isinstance(ptr, int):
            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'
            ptr = str_fmt.format(ptr)

        if not self._app_window.dwarf.dwarf_api('isAddressWatched', int(ptr, 16)):
            self.onAddWatcher.emit(ptr)
