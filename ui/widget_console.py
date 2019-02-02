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
from PyQt5.QtCore import Qt, QMargins
from PyQt5.QtWidgets import QListWidget, QListWidgetItem, QWidget, QLineEdit, QHBoxLayout, QPushButton, \
    QVBoxLayout, QScrollBar

from ui.dialog_js_editor import JsEditorDialog
from ui.widget_item_not_editable import NotEditableListWidgetItem


class QConsoleInputWidget(QLineEdit):
    def __init__(self, console_panel, callback, *__args):
        super().__init__(*__args)
        self.console_panel = console_panel
        self.callback = callback
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
            self.callback(self.text())
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


class QConsoleWidget(QWidget):
    def __init__(self, app, callback=None, input_placeholder='', function_box=False, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        layout = QVBoxLayout()

        self.app = app
        self.function_content = ''

        self.setContentsMargins(QMargins(0, 0, 0, 0))
        layout.setContentsMargins(QMargins(0, 0, 0, 0))

        self.list = QListWidget()
        self.list.setStyleSheet('''
            QListWidget::item:hover { 
                color: white; 
                background-color: rgba(255, 255, 255, 5); 
            }
            QListWidget::item:selected { 
                color: white; 
                background-color: rgba(255, 255, 255, 5); 
            }
        ''')
        bar = QScrollBar()
        bar.setMaximumHeight(0)
        bar.setMaximumWidth(0)
        self.list.setHorizontalScrollBar(bar)
        self.list.model().rowsInserted.connect(self.on_row_inserted)
        layout.addWidget(self.list)

        box = QHBoxLayout()
        box.setContentsMargins(QMargins(3, 3, 3, 3))

        if callback is not None:
            self.input = QConsoleInputWidget(self, callback)
            self.input.setPlaceholderText(input_placeholder)
            box.addWidget(self.input)

        if function_box:
            function_btn = QPushButton('ƒ')
            function_btn.setMinimumWidth(25)
            function_btn.clicked.connect(self.js_function_box)
            box.addWidget(function_btn)

        box_widget = QWidget()
        box_widget.setLayout(box)
        layout.addWidget(box_widget)

        self.setLayout(layout)

    def on_row_inserted(self, qindex, a, b):
        self.list.scrollToBottom()

    def log(self, what, clear=False):
        if clear:
            self.clear()

        if isinstance(what, QListWidgetItem):
            self.list.addItem(what)
        else:
            self.list.addItem(NotEditableListWidgetItem(str(what)))

    def clear(self):
        self.list.clear()

    def js_function_box(self):
        accept, what = JsEditorDialog(
            self.app, def_text=self.function_content,
            placeholder_text='// js script with both frida and dwarf api.\n'
                             '// note that it\'s evaluated. Which means, if you define a variable\n'
                             '// or attach an Interceptor, it won\'t be removed by '
                             'just deleting the script content').show()
        if accept:
            self.function_content = what
            if len(what) > 0:
                self.app.dwarf_api('evaluateFunction', what)

    def get_js_script_text(self):
        return self.function_content

    def set_js_script_text(self, script):
        self.function_content = script
