import argparse
import frida
import os
import qdarkstyle

from PyQt5.QtWidgets import QApplication

from lib.dwarf import Dwarf
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

    with open('lib/script.js', 'r') as f:
        s = f.read()
    script = process.create_script(s)
    script.load()

    app_window = AppWindow(script)
    app_window.showMaximized()

    if args.spawn:
        device.resume(args.package)

    app.exec_()

    script.exports.release()
    process.detach()
