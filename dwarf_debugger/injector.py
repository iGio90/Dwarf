"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""
from dwarf_debugger.lib.tool import Tool


class Injector(Tool):
    def parse_arguments(self, parser):
        parser.add_argument(
            "-s",
            "--script",
            type=str,
            help="Path to an additional script to load with dwarf and frida js api"
        )

        parser.add_argument(
            "-bs", "--break-start", action='store_true', help="break at start")

        parser.add_argument(
            "-ds",
            "--debug-script",
            action='store_true',
            help="debug outputs from frida script")

    def get_script(self):
        if self.arguments.script is not None:
            import os
            if os.path.exists(self.arguments.script):
                return open(self.arguments.script, 'r').read()


def main():
    Injector()
