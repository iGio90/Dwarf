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
from PyQt5.QtWidgets import *

from lib.prefs import Prefs


class EmulatorConfigsDialog(QDialog):
    def __init__(self, dwarf, parent=None):
        super(EmulatorConfigsDialog, self).__init__(parent)
        self.dwarf = dwarf
        self._prefs = Prefs()

        layout = QVBoxLayout(self)

        self.setMinimumWidth(500)

        layout.addWidget(QLabel('callbacks path'))
        callbacks_layout = QHBoxLayout()
        pick_path = QPushButton('choose')
        pick_path.clicked.connect(self.pick_callbacks_path)
        current_callbacks_path = self._prefs.get(prefs.EMULATOR_CALLBACKS_PATH)
        if current_callbacks_path == '':
            current_callbacks_path = 'none'
        self.callbacks_path_label = QLabel(current_callbacks_path)
        callbacks_layout.addWidget(pick_path)
        callbacks_layout.addWidget(self.callbacks_path_label)
        layout.addLayout(callbacks_layout)

        layout.addWidget(QLabel('delay between instructions'))
        self.instructions_delay = QLineEdit()
        self.instructions_delay.setText(str(self._prefs.get(prefs.EMULATOR_INSTRUCTIONS_DELAY, 0.5)))
        layout.addWidget(self.instructions_delay)

        buttons = QHBoxLayout()
        cancel = QPushButton('cancel')
        cancel.clicked.connect(self.close)
        buttons.addWidget(cancel)
        accept = QPushButton('accept')
        accept.clicked.connect(self.accept)
        buttons.addWidget(accept)

        layout.addLayout(buttons)

    def pick_callbacks_path(self):
        r = QFileDialog.getOpenFileName()
        if len(r) > 0 and len(r[0]) > 0:
            self._prefs.put(prefs.EMULATOR_CALLBACKS_PATH, r[0])
            self.callbacks_path_label.setText(r[0])

    @staticmethod
    def show_dialog(dwarf):
        dialog = EmulatorConfigsDialog(dwarf)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            try:
                self._prefs.put(prefs.EMULATOR_INSTRUCTIONS_DELAY, float(dialog.instructions_delay.text()))
            except:
                pass
