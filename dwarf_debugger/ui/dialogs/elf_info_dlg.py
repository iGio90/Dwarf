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

from PyQt5.Qt import Qt, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QHBoxLayout, QMenu

from dwarf_debugger.ui.widgets.list_view import DwarfListView
from dwarf_debugger.ui.dialogs.dwarf_dialog import DwarfDialog

from dwarf_debugger.lib import utils


class ElfInfo(DwarfDialog):
    onShowMemoryRequest = pyqtSignal(str, name='onShowMemoryRequest')

    def __init__(self, parent=None, file_path=None):
        super().__init__(parent=parent)
        h_box = QHBoxLayout(self)
        self._ident_titles = ['EI_MAG0', 'EI_MAG1', 'EI_MAG2', 'EI_MAG3', 'EI_CLASS', 'EI_DATA', 'EI_VERSION', 'EI_OSABI', 'EI_ABIVERSION', 'EI_PAD']
        self.elf_info = DwarfListView(self)
        self.elf_info.setRootIsDecorated(True)
        self.elf_info.setExpandsOnDoubleClick(True)
        self.elf_info.setContextMenuPolicy(Qt.CustomContextMenu)
        self.elf_info.customContextMenuRequested.connect(self._on_context_menu)
        h_box.addWidget(self.elf_info)
        self._elf_info_mdl = QStandardItemModel(0, 2)
        self._elf_info_mdl.setHeaderData(0, Qt.Horizontal, 'Name')
        self._elf_info_mdl.setHeaderData(1, Qt.Horizontal, 'Value')
        self.elf_info.setModel(self._elf_info_mdl)
        self.elf_info.doubleClicked.connect(self._on_dblclicked)
        self.title = "ELF Info"
        self._elf_file_path = None
        self.setLayout(h_box)
        if file_path:
            self.set_elf_file(file_path)

    def set_elf_file(self, file_path):
        self._elf_file_path = file_path
        self.title = 'ELF Info for ' + file_path
        self._elf_info_mdl.insertRow(0, [QStandardItem('File'), QStandardItem(file_path)])

    def set_parsed_data(self, parsed_data):
        parent_item = self._elf_info_mdl.item(0)
        if 'endian' in parsed_data:
            parent_item.appendRow([QStandardItem('Endian'), QStandardItem(parsed_data['endian'])])
        if 'is64bit' in parsed_data:
            txt = 'No'
            if parsed_data['is64bit']:
                txt = 'Yes'
            parent_item.appendRow([QStandardItem('64Bit'), QStandardItem(txt)])

        if 'header' in parsed_data:
            elf_header = QStandardItem('ELF Header')
            parent_item.appendRow([elf_header])
            for d in parsed_data['header']:
                if d == 'e_ident':
                    ident_item = QStandardItem(d)
                    elf_header.appendRow([ident_item, QStandardItem(str(parsed_data['header'][d]))])
                    a = 0
                    for i in parsed_data['header'][d]:
                        if a >= len(self._ident_titles):
                            a = len(self._ident_titles) - 1
                        ident_item.appendRow([QStandardItem(self._ident_titles[a]), QStandardItem(str(i))])
                        a += 1
                else:
                    elf_header.appendRow([QStandardItem(d), QStandardItem(hex(parsed_data['header'][d]))])

        if 'programheaders' in parsed_data:
            prog_headers_item = QStandardItem('Program Headers')
            parent_item.appendRow([prog_headers_item])
            i = 1
            for header in parsed_data['programheaders']:
                header_item = QStandardItem("%d" % i)
                prog_headers_item.appendRow([header_item])
                i += 1
                for d in header:
                    header_item.appendRow([QStandardItem(d), QStandardItem(hex(header[d]))])

        if 'sectionheaders' in parsed_data:
            sect_headers = QStandardItem('Section Headers')
            parent_item.appendRow([sect_headers])
            i = 1
            for header in parsed_data['sectionheaders']:
                txt = header['name']
                if not txt:
                    txt = 'NULL'
                header_item = QStandardItem(txt)
                sect_headers.appendRow([header_item])
                i += 1
                for d in header:
                    if d == 'name':
                        continue
                    elif d == 'data' and header[d]:
                        data_item = QStandardItem('Data')
                        header_item.appendRow(data_item)
                        base = self.parent().dwarf.dwarf_api('findModule', self._elf_file_path)['base']
                        for ptr in header[d]:
                            if int(ptr):
                                va = hex(int(base, 16) + int(ptr))
                                fo = hex(int(ptr))
                                if self.elf_info.uppercase_hex:
                                    va = va.upper().replace('0X', '0x')
                                    fo = fo.upper().replace('0X', '0x')
                                data_item.appendRow([QStandardItem(va), QStandardItem('FileOffset: ' + fo)])
                    else:
                        header_item.appendRow([QStandardItem(d), QStandardItem(hex(header[d]))])

            self.elf_info.expandAll()
            self.elf_info.resizeColumnToContents(0)
            self.elf_info.resizeColumnToContents(1)
            self.setMinimumWidth(self.elf_info.columnWidth(0) + self.elf_info.columnWidth(1) + 50)
            self.setMinimumHeight(400)
            self.elf_info.collapseAll()
            self.elf_info.expandToDepth(1)


    def _on_dblclicked(self, model_index):
        if model_index.column() == 0 and model_index.data():
            if model_index.data().startswith('0x'):
                self.onShowMemoryRequest.emit(model_index.data())

    def _on_context_menu(self, pos):
        model_index = self.elf_info.indexAt(pos)
        if model_index.column() == 0 and model_index.data():
            if model_index.data().startswith('0x'):
                context_menu = QMenu()
                context_menu.addAction('Add to Bookmarks', lambda: self.parent().bookmarks_panel.insert_bookmark(model_index.data(), 'init_array'))
                context_menu.addAction('Copy Address', lambda: utils.copy_hex_to_clipboard(model_index.data()))
                # show contextmenu
                glbl_pt = self.elf_info.mapToGlobal(pos)
                context_menu.exec_(glbl_pt)
