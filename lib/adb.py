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
import subprocess

from lib import utils
from lib.android import AndroidPackage


class Adb(object):
    def __init__(self, app):
        self.app = app

        try:
            adb = utils.do_shell_command('adb --version')
            self.adb_available = adb.index('Android Debug Bridge') >= 0
        except:
            self.adb_available = False

    def _do_adb_command(self, cmd, stdout=subprocess.PIPE):
        res = utils.do_shell_command(cmd, stdout=stdout)
        try:
            if res.index('no device') >= 0:
                return None
            return res
        except:
            return res

    def get_device_arch(self):
        if not self.adb_available:
            return None
        return self._do_adb_command('adb shell getprop ro.product.cpu.abi')

    def get_frida_version(self):
        if not self.adb_available:
            return None
        r = self._do_adb_command('adb shell frida --version')
        try:
            if len(r) == 0 or r.index('frida: not found') >= 0:
                return '0'
        except:
            return r

    def kill_package(self, package):
        if not self.adb_available:
            return None
        return self._do_adb_command("adb shell am force-stop " + package)

    def list_packages(self):
        if not self.adb_available:
            return None
        packages = self._do_adb_command('adb shell pm list packages -f')
        if packages:
            packages = packages.split('\n')
        else:
            packages = []
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

    def mount_system(self):
        if not self.adb_available:
            return None
        self.su("mount -o rw,remount /system")

    def pull(self, path, dest):
        if not self.adb_available:
            return None
        self._do_adb_command('adb pull %s %s' % (path, dest))

    def push(self, path, dest):
        if not self.adb_available:
            return None
        return self._do_adb_command('adb push %s %s' % (path, dest))

    def su(self, cmd, stdout=subprocess.PIPE):
        if not self.adb_available:
            return None
        return self._do_adb_command('adb shell su -c "' + cmd + '"', stdout=stdout)
