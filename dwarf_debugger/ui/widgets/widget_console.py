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
import datetime
from PyQt5.Qt import QFontMetrics
from PyQt5.QtCore import Qt, QMargins, pyqtSignal
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QPushButton, QVBoxLayout,
                             QPlainTextEdit, QSizePolicy)

from dwarf_debugger.ui.dialogs.dialog_js_editor import JsEditorDialog
from dwarf_debugger.ui.widgets.code_editor import JsCodeEditor
from dwarf_debugger.lib.utils import get_os_monospace_font


class DwarfConsoleInput(JsCodeEditor):
    """
    """

    onEnterKeyPressed = pyqtSignal(str, name='onEnterKeyPressed')

    def __init__(self, parent=None, completer=True):
        super().__init__(parent=parent, completer=completer)
        self.cmds = []
        self.cmd_index = 0
        self.setStyleSheet('padding: 0; padding: 0 5px;')
        # calc size for single line
        font_metric = QFontMetrics(self.font())
        row_height = font_metric.lineSpacing()
        self.setFixedHeight(row_height + 10)  # 10 == 2*5px padding

    def keyPressEvent(self, event):
        # when codecompletion popup dont respond to enter
        if self.completer and self.completer.popup() and self.completer.popup(
        ).isVisible():
            event.ignore()
            return super().keyPressEvent(event)

        if event.key() == Qt.Key_Enter or event.key() == Qt.Key_Return:
            cmd = self.toPlainText()
            l = len(self.cmds)
            if l > 0:
                if l > 100:
                    self.cmds.pop(0)
                if cmd != self.cmds[l - 1]:
                    self.cmds.append(cmd)
            else:
                self.cmds.append(cmd)
            self.cmd_index = 0
            self.onEnterKeyPressed.emit(cmd)
            self.setPlainText('')
        elif event.key() == Qt.Key_Up:
            l = len(self.cmds)
            try:
                self.setPlainText(self.cmds[l - 1 - self.cmd_index])
                if self.cmd_index < l - 1:
                    self.cmd_index += 1
            except:
                pass
        elif event.key() == Qt.Key_Down:
            try:
                if self.cmd_index >= 0:
                    self.cmd_index -= 1
                self.setPlainText(
                    self.cmds[len(self.cmds) - 1 - self.cmd_index])
            except:
                self.setPlainText('')
                self.cmd_index = 0
        else:
            return super().keyPressEvent(event)

    def clear_history(self):
        self.cmds.clear()


class DwarfConsoleWidget(QWidget):

    onCommandExecute = pyqtSignal(str, name='onCommandExecute')

    def __init__(self, parent=None, input_placeholder='', function_box=False, has_input=True, completer=True):
        super().__init__(parent=parent)

        self.app_window = parent

        layout = QVBoxLayout()

        self.function_content = ''
        self.script_file = None

        self.setContentsMargins(QMargins(0, 0, 0, 0))
        layout.setContentsMargins(QMargins(0, 0, 0, 0))

        # use textedit to allow copy contents
        self.output = QPlainTextEdit()
        self.output.setFont(get_os_monospace_font())
        self.output.setReadOnly(True)
        self.output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout.addWidget(self.output)

        if has_input:
            box = QHBoxLayout()
            box.setContentsMargins(QMargins(3, 3, 3, 3))

            self.input = DwarfConsoleInput(self, completer=completer)
            self.input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self.input.setPlaceholderText(input_placeholder)
            self.input.onEnterKeyPressed.connect(self._enter_pressed)
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

    def _enter_pressed(self, cmd):
        if cmd == 'clear':
            self.clear()
        else:
            self.onCommandExecute.emit(cmd)

    def log(self, what, clear=False, time_prefix=True):
        if clear:
            self.clear()

        what = str(what)

        # color up stuff
        if 'error:' in what.lower():
            html_text = '<font color="crimson">' + what + '</font>'
        else:
            html_text = what.replace('\n', '<br>')

        self.output.appendHtml(
            '<font color="#999"><p>' + (self.timestamp() if time_prefix else '') + html_text + '</p></font>')
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def timestamp(self):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
        return '<font color="yellowgreen">' + timestamp + '</font>&nbsp;&nbsp;'

    def clear(self):
        self.output.setPlainText('')

    def js_function_box(self):
        dialog = JsEditorDialog(
            self.app_window,
            def_text=self.function_content,
            file=self.script_file,
            placeholder_text='// js script with both frida and dwarf api.\n'
                             '// note that it\'s evaluated. Which means, if you define a variable\n'
                             '// or attach an Interceptor, it won\'t be removed by '
                             'just deleting the script content')
        accept, what = dialog.show()
        if self.script_file is None and dialog.file is not None:
            # script got saved
            self.script_file = dialog.file
        self.function_content = what
        if self.function_content:
            if accept:
                self.app_window.session_manager.session.dwarf.dwarf_api('evaluateFunction', self.function_content)
            if self.script_file is not None:
                with open(self.script_file, 'w') as f:
                    f.write(self.function_content)

    def get_js_script_text(self):
        return self.function_content

    def set_js_script_text(self, script):
        self.function_content = script
