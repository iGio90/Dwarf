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
import subprocess

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QAction, QMessageBox


app_icon = None


def get_app_icon():
    global app_icon
    if app_icon is None:
        app_icon = QPixmap("ui/dwarf.png").scaledToHeight(75, Qt.SmoothTransformation)
    return app_icon


def show_message_box(text, details=None):
    msg = QMessageBox()
    msg.setIconPixmap(get_app_icon())

    msg.setText(text)
    if details:
        msg.setDetailedText(details)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()


def get_qmenu_separator():
    separator = QAction("--------------------")
    separator.setEnabled(False)
    return separator


def do_shell_command(cmd, stdout=subprocess.PIPE):
    result = subprocess.run(cmd.split(' '), stdout=stdout)
    if stdout == subprocess.PIPE:
        return result.stdout.decode('utf8')
    else:
        return ''
