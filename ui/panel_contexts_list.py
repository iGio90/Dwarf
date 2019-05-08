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
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QTreeView, QHeaderView, QMenu

from ui.list_view import DwarfListView


class ContextsListPanel(DwarfListView):

    onItemDoubleClicked = pyqtSignal(dict, name='onItemDoubleClicked')

    def __init__(self, parent=None):
        super(ContextsListPanel, self).__init__(parent=parent)
        self._app_window = parent
        self.dwarf = parent.dwarf

        self.threads_model = QStandardItemModel(0, 3)
        self.threads_model.setHeaderData(0, Qt.Horizontal, 'TID')
        self.threads_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        if self.dwarf.arch == 'ia32':
            self.threads_model.setHeaderData(1, Qt.Horizontal, 'EIP')
        elif self.dwarf.arch == 'x64':
            self.threads_model.setHeaderData(1, Qt.Horizontal, 'RIP')
        else:
            self.threads_model.setHeaderData(1, Qt.Horizontal, 'PC')
        self.threads_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.threads_model.setHeaderData(2, Qt.Horizontal, 'Symbol')

        self.setModel(self.threads_model)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

        self.doubleClicked.connect(self._item_doubleclicked)

    def add_context(self, data, library_onload=None):
        if self.dwarf.arch == 'ia32':
            self.threads_model.setHeaderData(1, Qt.Horizontal, 'EIP')
        elif self.dwarf.arch == 'x64':
            self.threads_model.setHeaderData(1, Qt.Horizontal, 'RIP')
        else:
            self.threads_model.setHeaderData(1, Qt.Horizontal, 'PC')
        is_java = data['is_java']
        tid = QStandardItem()
        tid.setText(str(data['tid']))
        tid.setData(data, Qt.UserRole + 1)
        tid.setTextAlignment(Qt.AlignCenter)

        pc_col = QStandardItem()
        if not is_java:
            pc = int(data['ptr'], 16)
            if 'arm' in self.dwarf.arch:
                # dethumbify
                if pc & 1 == 1:
                    pc -= 1

            str_fmt = '0x{0:X}'
            if self._uppercase_hex:
                str_fmt = '0x{0:X}'
            else:
                str_fmt = '0x{0:x}'

            pc_col.setText(str_fmt.format(pc))
        else:
            parts = data['ptr'].split('.')
            pc_col.setText(parts[len(parts) - 1])

        symb_col = QStandardItem()
        if library_onload is None:
            if not is_java:
                str_fmt = ('{0} - {1}'.format(data['context']['pc']['symbol']['moduleName'], data['context']['pc']['symbol']['name']))
                symb_col.setText(str_fmt)
            else:
                symb_col.setText('.'.join(parts[:len(parts) - 1]))
        else:
            str_fmt = ('loading {0}'.format(library_onload))
            symb_col.setText(str_fmt)

        self.threads_model.appendRow([tid, pc_col, symb_col])
        self.resizeColumnToContents(0)
        self.resizeColumnToContents(1)

    def resume_tid(self, tid):
        if self.dwarf._spawned and not self.dwarf._resumed:
            self.dwarf.resume_proc()
            return

        # todo: check why removing here and removing in on_proc_resume
        for i in range(self.threads_model.rowCount()):
            is_tid = self.threads_model.item(i, 0).text()
            if is_tid == str(tid):
                self.threads_model.removeRow(i)

    def _item_doubleclicked(self, model_index):
        row = self.threads_model.itemFromIndex(model_index).row()
        if row != -1:
            context_data = self.threads_model.item(row, 0).data(Qt.UserRole + 1)
            self.onItemDoubleClicked.emit(context_data)

    def _on_context_menu(self, pos):
        index = self.indexAt(pos).row()
        if index != -1:
            tid = int(self.get_item_text(index, 0))
            glbl_pt = self.mapToGlobal(pos)
            context_menu = QMenu()
            context_menu.addAction('Emulator', self._on_cm_emulator)
            if self.dwarf.native_trace_tid == tid:
                context_menu.addAction('Stop Trace', self.dwarf.native_tracer_stop)
            else:
                context_menu.addAction('Trace', lambda: self._on_cm_starttrace(tid))
            context_menu.addSeparator()
            context_menu.addAction('Resume', lambda: self.dwarf.dwarf_api('release', tid))
            context_menu.exec_(glbl_pt)

    def _on_cm_starttrace(self, tid):
        self.dwarf.native_tracer_start(int(tid))

    def _on_cm_emulator(self):
        if self._app_window.emulator_panel is None:
            self._app_window._create_ui_elem('emulator')

        self._app_window.show_main_tab('emulator')
