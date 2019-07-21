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
import os
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, \
    QFileDialog, QSpinBox, QLabel, QWidget, QPlainTextEdit, QCompleter
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QFontDatabase, QPainter, QTextCursor
from PyQt5.QtCore import QFile, QRegExp, Qt, QRegularExpression, QRect, QSize, QStringListModel, pyqtSignal

from lib.utils import get_os_monospace_font
from lib.prefs import Prefs


class SmaliPanel(QPlainTextEdit):

    def __init__(self, parent=None):
        super(SmaliPanel, self).__init__(parent)
        self.setReadOnly(True)

    def set_file(self, file_name):
        if os.path.exists(file_name):
            with open(file_name, 'rt') as smali_file:
                self.setPlainText(smali_file.read())
