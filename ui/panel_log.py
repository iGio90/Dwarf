"""
Dwarf - Copyright (C) 2018 iGio90

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
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtWidgets import QListWidget, QListWidgetItem, QWidget, QVBoxLayout, QLineEdit, QStackedLayout, QLabel, \
    QHBoxLayout, QPushButton

from ui.dialog_input_multiline import InputMultilineDialog
from ui.widget_item_not_editable import NotEditableListWidgetItem


class JsInput(QLineEdit):
    def __init__(self, log_panel, *__args):
        super().__init__(*__args)
        self.log_panel = log_panel
        self.cmds = []
        self.cmd_index = 0

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Enter or event.key() == Qt.Key_Return:
            cmd = self.text()
            l = len(self.cmds)
            if l > 0:
                if l > 100:
                    self.cmds.pop(0)

                if cmd != self.cmds[l - 1]:
                    self.cmds.append(cmd)
            else:
                self.cmds.append(cmd)

            self.cmd_index = 0
            self.log_panel.app.dwarf_api('evaluate', self.text())
            self.setText('')
        elif event.key() == Qt.Key_Up:
            l = len(self.cmds)
            try:
                self.setText(self.cmds[l - 1 - self.cmd_index])
                if self.cmd_index < l - 1:
                    self.cmd_index += 1
            except:
                pass
        elif event.key() == Qt.Key_Down:
            try:
                if self.cmd_index >= 0:
                    self.cmd_index -= 1
                self.setText(self.cmds[len(self.cmds) - 1 - self.cmd_index])
            except:
                self.setText('')
                self.cmd_index = 0
        else:
            return super().keyPressEvent(event)

    def clear_history(self):
        self.cmds.clear()


class LogPanel(QWidget):
    def __init__(self, app, *args, **kwargs):
        super().__init__(None, *args, **kwargs)

        self.app = app

        box = QVBoxLayout()

        self.list = QListWidget()
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list.model().rowsInserted.connect(self.on_row_inserted)
        box.addWidget(self.list)

        js_box = QHBoxLayout()

        self.input = JsInput(self)
        self.input.setPlaceholderText('$>')
        js_box.addWidget(self.input)

        function_btn = QPushButton('ƒ')
        function_btn.setMinimumWidth(25)
        function_btn.clicked.connect(self.js_function_box)
        js_box.addWidget(function_btn)

        box.addLayout(js_box)

        self.setLayout(box)

    def on_row_inserted(self, qindex, a, b):
        self.list.scrollToBottom()

    def log(self, what, clear=False):
        if clear:
            self.clear()

        if isinstance(what, QListWidgetItem):
            self.list.addItem(what)
        else:
            self.list.addItem(NotEditableListWidgetItem(what))

    def clear(self):
        self.list.clear()

    def js_function_box(self):
        accepted, inp = InputMultilineDialog().input(min_width=500)
        if len(inp) > 0:
            self.app.dwarf_api('evaluateFunction', inp)
