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
import os

from PyQt5.QtWidgets import QDialog, QTextEdit, QVBoxLayout, QHBoxLayout, QPushButton, \
    QFileDialog


class JsEditorDialog(QDialog):
    def __init__(self, app, def_text='', placeholder_text='', flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.app = app

        self.input_widget = QTextEdit()

        self.input_widget.setText(def_text)
        self.input_widget.setPlaceholderText(placeholder_text)

        layout = QVBoxLayout()
        top_buttons = QHBoxLayout()
        bottom_buttons = QHBoxLayout()

        open = QPushButton('open')
        open.clicked.connect(self.handler_open)
        top_buttons.addWidget(open)
        save = QPushButton('save')
        save.clicked.connect(self.handler_save)
        top_buttons.addWidget(save)

        inject = QPushButton('inject')
        inject.clicked.connect(self.handler_inject)
        bottom_buttons.addWidget(inject)

        layout.addLayout(top_buttons)
        layout.addWidget(self.input_widget)
        layout.addLayout(bottom_buttons)

        self.setMinimumWidth(app.width() - (app.width() / 10))
        self.setMinimumHeight(app.height() - (app.height() / 10))

        self.setLayout(layout)

    def show(self):
        result = self.exec_()
        return result == QDialog.Accepted, self.input_widget.toPlainText()

    def keyPressEvent(self, event):
        super(JsEditorDialog, self).keyPressEvent(event)

    def handler_inject(self):
        self.accept()
        self.close()

    def handler_open(self):
        r = QFileDialog.getOpenFileName()
        if len(r) > 0 and len(r[0]) > 0:
            with open(r[0], 'r') as f:
                self.input_widget.setText(f.read())

    def handler_save(self):
        r = QFileDialog.getSaveFileName()
        if len(r) > 0 and len(r[0]) > 0:
            with open(r[0], 'w') as f:
                f.write(self.input_widget.toPlainText())
