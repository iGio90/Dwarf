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
from PyQt5 import QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *


class InputDialogTextEdit(QTextEdit):
    def __init__(self, dialog, *__args):
        super().__init__(*__args)
        self.dialog = dialog

        bar = QScrollBar()
        bar.setFixedHeight(0)
        bar.setFixedWidth(0)
        self.setHorizontalScrollBar(bar)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setLineWrapMode(QTextEdit.NoWrap)
        # self.setFixedHeight(28)
        self.setMinimumWidth(350)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Return:
            self.dialog.accept()
        else:
            super(InputDialogTextEdit, self).keyPressEvent(event)


class InputDialog(QDialog):
    def __init__(self, parent=None, hint=None, input_content='', placeholder='', options_callback=None):
        super(InputDialog, self).__init__(parent)

        box = QVBoxLayout(self)
        if hint:
            box.addWidget(QLabel(hint))

        # wtf this hack to prevent segfault on adding hook with shortcuts from hooks panel.
        # use qtextedit instead of qlineedit won't cause issues
        self.input_widget = InputDialogTextEdit(self)

        self.input_widget.setPlaceholderText(placeholder)
        if len(input_content) > 0:
            self.input_widget.setText(input_content)

        box.addWidget(self.input_widget)

        buttons = QHBoxLayout()
        ok = QPushButton('ok')
        buttons.addWidget(ok)
        if options_callback:
            options = QPushButton('options')
            options.clicked.connect(options_callback)
            buttons.addWidget(options)
        ok.clicked.connect(self.accept)
        cancel = QPushButton('cancel')
        cancel.clicked.connect(self.close)
        buttons.addWidget(cancel)
        box.addLayout(buttons)
        self.setLayout(box)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Return:
            self.accept()
        else:
            super(InputDialog, self).keyPressEvent(event)

    @staticmethod
    def input(parent=None, hint=None, input_content='', placeholder='', options_callback=None):
        dialog = InputDialog(parent=parent, hint=hint, input_content=input_content,
                             placeholder=placeholder, options_callback=options_callback)
        result = dialog.exec_()
        text = dialog.input_widget.toPlainText()
        return result == QDialog.Accepted, text

    @staticmethod
    def input_pointer(parent=None, input_content='', hint='insert pointer'):
        accept, inp = InputDialog.input(
            parent=parent,
            hint=hint,
            input_content=input_content,
            placeholder='Module.findExportByName(\'target\', \'export\')')
        if not accept:
            return 0, ''
        try:
            return int(parent.dwarf.dwarf_api('evaluatePtr', inp), 16), inp
        except:
            return 0, ''
