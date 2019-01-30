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
import subprocess
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QAction, QMessageBox

app_icon = None


def do_shell_command(cmd, stdout=subprocess.PIPE):
    if stdout == subprocess.PIPE:
        '''
        This solution is a shit because we don't know why on the following case:
        on ubuntu + py 3.6, running adb shell with subprocess run and redirect stdout and stderr to pipe
        return none and output the result on the console (O.O). On OSX i'm not facing this. 
        Windows users have the problem as well. The following code works for everyone :S  
        '''
        p = subprocess.Popen(cmd.split(' '),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE)
        out, err = p.communicate()
        out = out.decode('utf8')
        if len(out) > 0:
            return out
        return err.decode('utf8')

    result = subprocess.run(cmd.split(' '), stdout=stdout)
    if stdout == subprocess.PIPE:
        return result.stdout.decode('utf8')
    else:
        return ''


def get_app_icon():
    global app_icon
    if app_icon is None:
        app_icon = QPixmap(resource_path('ui/dwarf.png')).scaledToHeight(75, Qt.SmoothTransformation)
    return app_icon


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def show_message_box(text, details=None):
    msg = QMessageBox()
    msg.setIconPixmap(get_app_icon())

    msg.setText(text)
    if details:
        msg.setDetailedText(details)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()
    return None


def parse_ptr(ptr):
    if isinstance(ptr, str):
        if ptr.startswith('#'):
            ptr = ptr[1:]
        if ptr.startswith('0x'):
            ptr = int(ptr, 16)
        else:
            try:
                ptr = int(ptr)
            except:
                ptr = 0
    if not isinstance(ptr, int):
        ptr = 0
    return ptr
