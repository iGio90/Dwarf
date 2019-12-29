import os
import sys

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QHBoxLayout, QRadioButton, QPushButton

from dwarf_debugger.lib import utils
from dwarf_debugger.ui.dialogs.dwarf_dialog import DwarfDialog


class SetupDialog(DwarfDialog):
    def __init__(self, prefs, parent=None):
        super(SetupDialog, self).__init__(parent)
        self.prefs = prefs
        current_theme = self.prefs.get('dwarf_ui_theme', 'black')
        utils.set_theme(current_theme)

        self.setMinimumWidth(400)

        box = QVBoxLayout()
        box.setContentsMargins(10, 10, 10, 10)

        theme_container = QVBoxLayout()
        theme_container.setContentsMargins(0, 0, 0, 0)
        theme_label = QLabel('Theme')
        font = QFont('OpenSans', 20, QFont.Bold)
        font.setPixelSize(20)
        theme_label.setFont(font)
        theme_container.addWidget(theme_label)

        theme_box = QHBoxLayout()
        theme_box.setContentsMargins(0, 10, 0, 0)
        dark = QRadioButton('Dark')
        if current_theme == 'dark':
            dark.setChecked(True)
        dark.toggled.connect(lambda x: self.theme_checked(x, 'dark'))
        theme_box.addWidget(dark)
        black = QRadioButton('Black')
        if current_theme == 'black':
            dark.setChecked(True)
        black.toggled.connect(lambda x: self.theme_checked(x, 'black'))
        theme_box.addWidget(black)
        light = QRadioButton('Light')
        if current_theme == 'light':
            light.setChecked(True)
        light.toggled.connect(lambda x: self.theme_checked(x, 'light'))
        theme_box.addWidget(light)
        theme_container.addLayout(theme_box)

        box.addLayout(theme_container)

        if sys.platform == 'linux':
            dwarf_bin_path = os.path.join('/'.join(os.path.realpath(__file__).split('/')[:-2]), 'bin/dwarf')
            if not os.path.exists(dwarf_bin_path):
                self.launcher_box = QVBoxLayout()
                self.launcher_box.setContentsMargins(0, 40, 0, 0)
                launcher_label = QLabel('Launcher')
                font = QFont('OpenSans', 20, QFont.Bold)
                font.setPixelSize(20)
                launcher_label.setFont(font)
                self.launcher_box.addWidget(launcher_label)
                self.launcher_box.addWidget(QLabel('Create dwarf alias and add to $path (dwarf --version)'))

                self.launcher_box.addWidget(self.btn_launcher_create)
                box.addLayout(self.launcher_box)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 30, 0, 0)

        finish = QPushButton('Finish')
        finish.clicked.connect(self.accept)
        buttons.addWidget(finish)

        box.addLayout(buttons)

        self.setLayout(box)

    def theme_checked(self, checkState, theme):
        utils.set_theme(theme, prefs=self.prefs)

    @staticmethod
    def showDialog(prefs, parent=None):
        dialog = SetupDialog(prefs, parent=parent)
        dialog.title = 'Setup'
        dialog.exec_()
