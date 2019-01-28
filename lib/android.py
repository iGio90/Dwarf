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

from lib import utils, external_tools


class AndroidPackage(object):
    def __init__(self):
        self.path = ''
        self.package = ''


class AndroidDecompileUtil(object):
    @staticmethod
    def decompile(adb, apk_path):
        if not os.path.exists('.decompile'):
            os.mkdir('.decompile')
        adb.pull(apk_path, '.decompile/base.apk')
        dex2jar = 'd2j-dex2jar.sh'
        if os.name == 'nt':
            dex2jar = 'd2j-dex2jar.bat'
        try:
            utils.do_shell_command(dex2jar).index('version')
        except:
            utils.show_message_box('failed to find %s' % dex2jar)
            return
        utils.do_shell_command('d2j-dex2jar.sh %s' % '.decompile/base.apk -o .decompile/base.jar -f')
        if not external_tools.tool_exist('luyten.jar'):
            external_tools.get_tool('https://github.com/deathmarine/Luyten/releases/download/v0.5.3/luyten-0.5.3.jar',
                                    'luyten.jar')
        java_version = utils.do_shell_command('java -version')
        try:
            java_version.index('java version')
        except:
            utils.show_message_box('failed to find java')
            return

        utils.do_shell_command('java -jar tools/luyten.jar .decompile/base.jar &')
