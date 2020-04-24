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
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QTreeView, QHeaderView, QMenu

from dwarf_debugger.ui.widgets.list_view import DwarfListView


class ThreadsWidget(DwarfListView):

    onItemDoubleClicked = pyqtSignal(dict, name='onItemDoubleClicked')

    def __init__(self, parent=None):
        super(ThreadsWidget, self).__init__(parent=parent)
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

        self.doubleClicked.connect(self._item_double_clicked)

    def add_context(self, data):
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
            if data['reason'] == 2:
                pc_col.setText(data['ptr'])
            else:
                pc = int(data['ptr'], 16)
                if 'arm' in self.dwarf.arch:
                    # dethumbify
                    if pc & 1 == 1:
                        pc -= 1

                if self._uppercase_hex:
                    str_fmt = '0x{0:X}'
                else:
                    str_fmt = '0x{0:x}'

                pc_col.setText(str_fmt.format(pc))
        else:
            parts = data['ptr'].split('.')
            pc_col.setText(parts[len(parts) - 1])

        symb_col = QStandardItem()
        if True:
            if not is_java:
                if 'symbol' in data['context']['pc']:
                    str_fmt = ('{0} - {1}'.format(
                        data['context']['pc']['symbol']['moduleName'], data['context']['pc']['symbol']['name']))
                    symb_col.setText(str_fmt)
            else:
                symb_col.setText('.'.join(parts[:len(parts) - 1]))
        else:
            str_fmt = ('loading {0}'.format(''))
            # str_fmt = ('loading {0}'.format(library_onload))
            symb_col.setText(str_fmt)

        self.threads_model.appendRow([tid, pc_col, symb_col])
        self.resizeColumnToContents(0)
        self.resizeColumnToContents(1)
        self.setCurrentIndex(self.threads_model.index(self.threads_model.rowCount()-1, 0))

    def resume_tid(self, tid):
        # todo: check why removing here and removing in on_proc_resume
        for i in range(self.threads_model.rowCount()):
            item = self.threads_model.item(i, 0)
            if item is None:
                continue
            is_tid = item.text()
            if is_tid == str(tid):
                self.threads_model.removeRow(i)

    def _item_double_clicked(self, model_index):
        row = self.threads_model.itemFromIndex(model_index).row()
        if row != -1:
            context_data = self.threads_model.item(row, 0).data(Qt.UserRole + 1)
            if self.dwarf.context_tid != context_data['tid']:
                self.onItemDoubleClicked.emit(context_data)

    def _on_context_menu(self, pos):
        index = self.indexAt(pos).row()
        if index != -1:
            item = self.threads_model.item(index, 0)
            tid = int(item.text())
            data = item.data(Qt.UserRole + 1)
            is_java = data['is_java']
            glbl_pt = self.mapToGlobal(pos)
            context_menu = QMenu()
            context_menu.addAction('Resume', lambda: self.dwarf.dwarf_api('release', tid))
            context_menu.exec_(glbl_pt)

    def _on_cm_start_trace(self, tid):
        self.dwarf.native_tracer_start(int(tid))

    def _on_cm_stop_trace(self):
        self.dwarf.native_tracer_stop()
