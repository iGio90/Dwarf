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
import sys
import argparse
from PyQt5.QtWidgets import QApplication

from ui.app import AppWindow


def process_args():
    """ process commandline params
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-t",
        "--type",
        type=str,
        help="SessionType - android, ios, local, remote - default: local")

    parser.add_argument(
        "-s",
        "--script",
        type=str,
        help="Path to an additional script to load with dwarf and frida js api"
    )

    parser.add_argument(
        "-p", "--package", help="Attach Dwarf to given packagename")
    #parser.add_argument("-a", "--attach", type=int, help="Attach Dwarf to given pid")

    parser.add_argument(
        "-sp", "--spawn", action='store_true', help="force spawn")

    args = parser.parse_args()
    return args


def _on_restart():
    os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def run_dwarf():
    """ fire it up
    """
    args = process_args()

    qapp = QApplication([])

    app_window = AppWindow(args)
    app_window.onRestart.connect(_on_restart)

    try:
        sys.exit(qapp.exec_())
    except SystemExit as sys_err:
        if sys_err.code == 0:
            # thanks for using dwarf
            print('Thank\'s for using Dwarf\nHave a nice day...')
        else:
            # something was wrong
            print('sysexit with: %d' % sys_err.code)


if __name__ == '__main__':
    run_dwarf()
