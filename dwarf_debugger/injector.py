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


def main():
    import argparse

    from dwarf_debugger.lib import glue

    def process_args():
        """ process commandline params
        """
        parser = glue.ArgParser()

        glue.put_default_arguments(parser)

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

        args = parser.parse_args()
        return args

    ########
    # INIT #
    ########
    args = process_args()

    if not args.target and not args.device:
        print('missing session type. use -t local|android|ios|remote to define the session type'
              ' or specify a device id with --device')
        exit(0)

    if args.any == '':
        print('missing file or package name to attach')
        exit(0)

    user_script = None
    if args.script is not None:
        import os
        if os.path.exists(args.script):
            user_script = open(args.script, 'r').read()

    glue.init(args, user_script)
