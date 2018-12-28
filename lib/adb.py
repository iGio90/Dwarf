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
from lib import utils
from lib.android_package import AndroidPackage


class Adb(object):
    def __init__(self, app):
        self.app = app

        adb = utils.do_shell_command('adb --version')
        try:
            self.adb_available = adb.index('Android Debug Bridge') >= 0
        except:
            self.adb_available = False

    def list_packages(self):
        if not self.adb_available:
            self.app.get_log_panel().log('adb not found')
            return None
        packages = utils.do_shell_command('adb shell pm list packages -f').split('\n')
        ret = []
        for package in packages:
            parts = package.split(':')
            if len(parts) < 2:
                continue
            needed = parts[1].split('.apk=')
            p = AndroidPackage()
            p.path = needed[0] + '.apk'
            p.package = needed[1]
            ret.append(p)
        return ret

    def pull(self, path, dest):
        if not self.adb_available:
            self.app.get_log_panel().log('adb not found')
            return None
        return utils.do_shell_command('adb pull %s %s' % (path, dest))
