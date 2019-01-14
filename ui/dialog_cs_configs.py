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
import capstone

from PyQt5 import QtCore
from PyQt5.QtWidgets import *


class CsConfigsDialog(QDialog):
    def __init__(self, parent=None, arch='', mode=''):
        super(CsConfigsDialog, self).__init__(parent)

        layout = QVBoxLayout(self)
        arch_mode_layout = QHBoxLayout()

        self.setMinimumWidth(350)

        cs_objs = dir(capstone)

        self.arch = QComboBox(self)
        for w in cs_objs:
            if w.startswith('CS_ARCH_'):
                self.arch.addItem(w.replace('CS_ARCH_', '').lower())
                if getattr(capstone, w) == arch:
                    self.arch.setCurrentIndex(self.arch.count() - 1)
        arch_mode_layout.addWidget(self.arch)

        self.mode = QComboBox(self)
        for w in cs_objs:
            if w.startswith('CS_MODE_'):
                self.mode.addItem(w.replace('CS_MODE_', '').lower())
                if getattr(capstone, w) == mode:
                    self.mode.setCurrentIndex(self.mode.count() - 1)
        arch_mode_layout.addWidget(self.mode)

        layout.addLayout(arch_mode_layout)

        buttons = QHBoxLayout()
        ok = QPushButton('Ok')
        buttons.addWidget(ok)
        ok.clicked.connect(self.accept)
        cancel = QPushButton('cancel')
        cancel.clicked.connect(self.close)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def keyPressEvent(self, event):
        super(CsConfigsDialog, self).keyPressEvent(event)
        if event.key() == QtCore.Qt.Key_Return:
            self.accept()

    @staticmethod
    def show_dialog(arch='', mode=''):
        dialog = CsConfigsDialog(arch=arch, mode=mode)
        result = dialog.exec_()

        return result == QDialog.Accepted, \
               getattr(capstone, 'CS_ARCH_%s' % dialog.arch.currentText().upper()), \
               getattr(capstone, 'CS_MODE_%s' % dialog.mode.currentText().upper())
