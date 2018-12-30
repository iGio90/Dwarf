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
import subprocess

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

    def get_device_arch(self):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        return utils.do_shell_command('adb shell getprop ro.product.cpu.abi')

    def get_frida_version(self):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        return utils.do_shell_command('adb shell frida --version')

    def kill_package(self, package):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        utils.do_shell_command("adb shell am force-stop " + package)

    def list_packages(self):
        if not self.adb_available:
            utils.show_message_box('adb not found')
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

    def mount_system(self):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        return utils.do_shell_command('adb shell su -c mount -o rw,remount /system')

    def pull(self, path, dest):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        return utils.do_shell_command('adb pull %s %s' % (path, dest))

    def push(self, path, dest):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        return utils.do_shell_command('adb push %s %s' % (path, dest))

    def su(self, cmd, stdout=subprocess.PIPE):
        if not self.adb_available:
            utils.show_message_box('adb not found')
            return None
        return utils.do_shell_command('adb shell su -c ' + cmd, stdout=stdout)
