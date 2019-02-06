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

from ui.ui_session import SessionUi
from ui.widget_context import ContextItem
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class ContextsListPanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 0)

    def set_menu_actions(self, item, menu):
        if item is not None:
            ctx = self.item(item.row(), 0)
            if isinstance(ctx, ContextItem):
                emulator = menu.addAction('Emulator')
                if self.app.get_emulator_panel() is not None:
                    emulator.setEnabled(False)
                else:
                    emulator.setData('emulator')
                if self.app.get_dwarf().get_native_traced_tid() > 0:
                    trace = menu.addAction("Stop trace")
                else:
                    trace = menu.addAction("Trace")
                trace.setData('trace')
                menu.addSeparator()
                resume = menu.addAction("Resume")
                resume.setData('resume')

    def on_menu_action(self, action_data, item):
        ctx = self.item(item.row(), 0)
        if isinstance(ctx, ContextItem):
            if action_data == 'emulator':
                self.app.get_session_ui().add_dwarf_tab(SessionUi.TAB_EMULATOR, request_focus=True)
            elif action_data == 'trace':
                if self.app.get_dwarf().get_native_traced_tid() > 0:
                    self.app.get_dwarf().native_tracer_stop()
                else:
                    tid = ctx.get_tid()
                    self.app.get_dwarf().native_tracer_start(tid)
            elif action_data == 'resume':
                self.app.resume(ctx.get_tid())
                return False

    def resume_tid(self, tid):
        items = self.findItems(str(tid), Qt.MatchExactly)
        if len(items) > 0:
            self.removeRow(items[0].row())

    def add_context(self, data, library_onload=None):
        if self.columnCount() == 0:
            self.setColumnCount(3)
            self.setHorizontalHeaderLabels(['tid', 'pc', 'symbol'])

        is_java = data['is_java']

        row = self.rowCount()
        self.insertRow(row)
        q = ContextItem(data, str(data['tid']))
        q.setForeground(Qt.darkCyan)
        self.setItem(row, 0, q)

        if not is_java:
            pc = int(data['ptr'], 16)
            # dethumbify
            if pc & 1 == 1:
                pc -= 1
            q = MemoryAddressWidget(hex(pc))
        else:
            parts = data['ptr'].split('.')
            q = NotEditableTableWidgetItem(parts[len(parts) - 1])
            q.setForeground(Qt.red)
            q.setFlags(Qt.NoItemFlags)
        self.setItem(row, 1, q)

        if library_onload is None:
            if not is_java:
                q = NotEditableTableWidgetItem('%s - %s' % (
                    data['context']['pc']['symbol']['moduleName'], data['context']['pc']['symbol']['name']))
            else:
                q = NotEditableTableWidgetItem('.'.join(parts[:len(parts) - 1]))
        else:
            q = NotEditableTableWidgetItem('loading %s' % library_onload)

        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.gray)
        self.setItem(row, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def item_double_clicked(self, item):
        if isinstance(item, ContextItem):
            self.app.apply_context(item.get_context())
            return False
        return True

    def clear(self):
        self.setRowCount(0)
        self.setColumnCount(0)
        self.resizeColumnsToContents()
        self.horizontalHeader().setStretchLastSection(True)
