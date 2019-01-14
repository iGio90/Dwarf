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
from PyQt5.QtWidgets import *


class InputMultilineDialog(QDialog):
    def __init__(self, parent=None, hint=None, input_content='', min_width=0):
        super(InputMultilineDialog, self).__init__(parent)

        layout = QVBoxLayout(self)

        if hint:
            layout.addWidget(QLabel(hint))
        self.input_widget = QTextEdit(self)
        if min_width > 0:
            self.input_widget.setMinimumWidth(min_width)

        if len(input_content) > 0:
            self.input_widget.setText(input_content)
        layout.addWidget(self.input_widget)

    def keyPressEvent(self, event):
        super(InputMultilineDialog, self).keyPressEvent(event)
        if event.key() == QtCore.Qt.Key_Escape:
            self.accept()

    @staticmethod
    def input(hint=None, input_content='', min_width=0):
        dialog = InputMultilineDialog(hint=hint, input_content=input_content, min_width=min_width)
        result = dialog.exec_()

        return result == QDialog.Accepted, \
               dialog.input_widget.toPlainText()
