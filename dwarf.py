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
import argparse
import sys

import qdarkstyle

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication

from lib import utils
from ui.app import AppWindow

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--script", action='store_true', help="an additional script to load with "
                                                                    "dwarf and frida js api")
    parser.add_argument("-p", "--package", help="package name or pid")
    args = parser.parse_args()

    app = QApplication([])
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    with open('ui/style.qss', 'r') as f:
        app.setStyleSheet(app.styleSheet() + '\n' + f.read())
    app.setWindowIcon(QIcon(utils.resource_path('ui/dwarf.png')))

    app_window = AppWindow(args)
    app_window.showMaximized()
    app.exec_()
    app_window.get_app_instance().get_dwarf().detach()
