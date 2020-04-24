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
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QHeaderView, QMenu

from dwarf_debugger.ui.widgets.list_view import DwarfListView

from dwarf_debugger.lib import utils


class RangesPanel(DwarfListView):
    """ RangesPanel

        Signals:
            onItemDoubleClicked(str) - only fired when prot has +r
            onDumpBinary([ptr, size#int]) - MenuItem DumpBinary
            onAddWatchpoint(str) - MenuItem AddWatchpoint
    """

    onItemDoubleClicked = pyqtSignal(str, name='onItemDoubleClicked')
    onDumpBinary = pyqtSignal(list, name='onDumpBinary')
    onAddWatchpoint = pyqtSignal(str, name='onAddWatchpoint')

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

        self.update_ranges()

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

            self.resizeColumnToContents(0)
            self.resizeColumnToContents(1)
            self.resizeColumnToContents(2)
            self.resizeColumnToContents(3)
            self.resizeColumnToContents(4)

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
                'Add Watchpoint', lambda: self._on_addwatchpoint(
                    self._ranges_model.item(index, 0).text()))

            context_menu.addAction(
                'Copy address', lambda: utils.copy_hex_to_clipboard(
                    self._ranges_model.item(index, 0).text()))
            context_menu.addSeparator()

            if self._ranges_model.item(index, 5):
                file_path = self._ranges_model.item(index, 5).text()
                if file_path:
                    context_menu.addAction(
                        'Copy Path', lambda: utils.copy_str_to_clipboard(
                            file_path))
                    context_menu.addSeparator()
                    if self._app_window.dwarf._platform == 'linux':
                        context_menu.addAction(
                            'Show ELF Info', lambda: self._on_parse_elf(
                                file_path))
                        context_menu.addSeparator()

            if self.search_enabled:
                context_menu.addSeparator()
                context_menu.addAction('Search', self._on_cm_search)
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

    def _on_addwatchpoint(self, ptr):
        """ MenuItem AddWatchpoint
        """
        if isinstance(ptr, int):
            str_fmt = '0x{0:X}'
            if not self.uppercase_hex:
                str_fmt = '0x{0:x}'
            ptr = str_fmt.format(ptr)

        if not self._app_window.dwarf.dwarf_api('isAddressWatched', int(
                ptr, 16)):
            self.onAddWatchpoint.emit(ptr)

    def _on_parse_elf(self, elf_path):
        from dwarf_debugger.ui.dialogs.elf_info_dlg import ElfInfo
        parsed_infos = self._app_window.dwarf.dwarf_api('parseElf', elf_path)
        if parsed_infos:
            elf_dlg = ElfInfo(self._app_window, elf_path)
            elf_dlg.onShowMemoryRequest.connect(self.onItemDoubleClicked)
            elf_dlg.set_parsed_data(parsed_infos)
            elf_dlg.show()
