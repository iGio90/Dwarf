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
import argparse
import frida
import os
import qdarkstyle

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication
from ui.app import AppWindow

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--spawn", action='store_true', help="spawn the process instead of attach")
    parser.add_argument("package", help="package name or pid")
    args = parser.parse_args()

    device = frida.get_usb_device()

    if args.spawn:
        os.system("adb shell am force-stop " + args.package)
        pid = device.spawn([args.package])
        process = device.attach(pid)
    else:
        process = device.attach(args.package)

    app = QApplication([])
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    app.setWindowIcon(QIcon('ui/dwarf.png'))

    with open('lib/script.js', 'r') as f:
        s = f.read()
    script = process.create_script(s)
    script.load()

    app_window = AppWindow(script)
    app_window.showMaximized()

    if args.spawn:
        device.resume(args.package)

    app.exec_()

    app_window.app.dwarf_api('release')
    process.detach()
