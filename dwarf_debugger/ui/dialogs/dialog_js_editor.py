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
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFontDatabase
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, \
    QFileDialog, QSpinBox, QLabel

from dwarf_debugger.ui.dialogs.dialog_scripts import ScriptsDialog
from dwarf_debugger.ui.dialogs.dwarf_dialog import DwarfDialog
from dwarf_debugger.ui.widgets.code_editor import JsCodeEditor


class JsEditorDialog(DwarfDialog):
    def __init__(self, app_window, def_text='', placeholder_text='', file=None, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.title = 'CodeEditor'
        self._app_window = app_window
        self.file = file

        font_size_pref = self._app_window.prefs.get('dwarf_ui_theme_editor_fs')
        if font_size_pref:
            try:
                font_size_pref = int(font_size_pref)
            except ValueError:
                # default size
                font_size_pref = 11

        # todo: add font selector
        self.editor_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        """
        self.editor_font = QFont()
        self.editor_font.setFamily('Courier')
        self.editor_font.setFixedPitch(True)
        """

        if font_size_pref:
            if font_size_pref >= 9 and font_size_pref <= 15:
                self.editor_font.setPointSize(font_size_pref)
            else:
                self.editor_font.setPointSize(11)
        else:
            # default size
            self.editor_font.setPointSize(11)

        self.input_widget = JsCodeEditor(completer=False)
        self.input_widget.setMinimumSize(800, 450)
        self.input_widget.line_numbers = True
        self.input_widget.setFont(self.editor_font)
        self.input_widget.setPlainText(def_text)
        self.input_widget.setPlaceholderText(placeholder_text)

        layout = QVBoxLayout()
        top_buttons = QHBoxLayout()
        bottom_buttons = QHBoxLayout()

        open_button = QPushButton('open')
        open_button.clicked.connect(self.handler_open)
        top_buttons.addWidget(open_button)
        if file is None:
            self.btn_save = QPushButton('save')
            self.btn_save.clicked.connect(self.handler_save)
            top_buttons.addWidget(self.btn_save)
        dwarf = QPushButton('dwarf')
        dwarf.clicked.connect(self.handler_dwarf_scripts)
        top_buttons.addWidget(dwarf)

        inject = QPushButton('inject')
        inject.clicked.connect(self.handler_inject)
        bottom_buttons.addWidget(inject)

        box = QHBoxLayout()
        fzl = QLabel('Font Size (pt):')
        fzl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        fzl.setFixedWidth(100)
        box.addWidget(fzl)
        font_size = QSpinBox()
        font_size.setRange(9, 15)
        font_size.setSingleStep(1)
        font_size.setValue(self.editor_font.pointSize())
        font_size.setFixedWidth(40)
        font_size.valueChanged.connect(self.change_font_size)
        box.addWidget(font_size)
        bottom_buttons.addLayout(box)

        layout.addLayout(top_buttons)
        layout.addWidget(self.input_widget)
        layout.addLayout(bottom_buttons)

        #self.setMinimumWidth(app.width() - (app.width() / 10))
        #self.setMinimumHeight(app.height() - (app.height() / 10))

        self.setLayout(layout)

    def change_font_size(self, size):
        if size >= 9 and size <= 15:
            self._app_window.prefs.put('dwarf_ui_theme_editor_fs', size)
            self.editor_font.setPointSize(size)
            self.input_widget.setFont(self.editor_font)
        self.input_widget.setTabStopDistance(self.input_widget.fontMetrics().width('9999'))
        self.input_widget.repaint()

    def show(self):
        result = self.exec_()
        return result == QDialog.Accepted, self.input_widget.toPlainText()

    def keyPressEvent(self, event):
        super(JsEditorDialog, self).keyPressEvent(event)

    def handler_dwarf_scripts(self):
        accept, script = ScriptsDialog.pick(self._app_window)
        if accept and script is not None:
            self.input_widget.setPlainText(script)

    def handler_inject(self):
        self.accept()
        self.close()

    def handler_open(self):
        r = QFileDialog.getOpenFileName()
        if len(r) > 0 and len(r[0]) > 0:
            with open(r[0], 'r') as f:
                self.input_widget.setPlainText(f.read())

    def handler_save(self):
        r = QFileDialog.getSaveFileName()
        if len(r) > 0 and len(r[0]) > 0:
            with open(r[0], 'w') as f:
                f.write(self.input_widget.toPlainText())
            self.btn_save.setVisible(False)
            self.file = r[0]
