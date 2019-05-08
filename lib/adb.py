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
from PyQt5.QtCore import QObject
from lib import utils
from lib.android import AndroidPackage


class Adb(QObject):
    """ adb handling
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self, parent=None):
        super(Adb, self).__init__(parent=parent)
        self._adb_available = False
        self._dev_emu = False
        self._is_root = False
        self._is_su = False

        self._have_pidof = False

        self._android_version = ''
        self._sdk_version = ''
        self._oreo_plus = False

        self._check_requirements()

    def _check_requirements(self):  # pylint: disable=too-many-branches, too-many-statements
        """ Checks for adb and root on device
        """
        self._adb_available = False
        self._dev_emu = False
        self._is_root = False
        self._is_su = False
        try:
            adb_version = utils.do_shell_command('adb --version')
            if adb_version is not None:
                if adb_version and 'Android Debug Bridge' in adb_version:
                    self._adb_available = True
                else:
                    self._adb_available = False

        # io error is handled here not in do_shell_command
        # if adb isnt there it gives file not found
        except IOError as io_error:
            # file not found
            if io_error.errno == 2:
                self._adb_available = False

        if self._adb_available:
            # try some su command
            res = utils.do_shell_command(
                'adb shell su -c \'mount -o ro,remount /system\'')
            if res is not None:
                # adb not authorized
                if res and 'device unauthorized' in res:
                    # kill adb daemon
                    utils.do_shell_command('adb kill-server')
                    utils.show_message_box(
                        'device not authorized! allow access from this computer on the device'
                    )

                if res and 'no devices/emulators' in res:
                    self._dev_emu = False
                elif res and 'device not found' in res:
                    self._dev_emu = False
                else:
                    self._dev_emu = True

                # user can run su?
                if res and 'Permission denied' in res:
                    self._is_su = False
                elif res and 'su: not found' in res:
                    self._is_su = False
                else:
                    if self._dev_emu:
                        self._is_su = True

                # no su -> try if the user is already root
                # on some emulators user is root
                if not self._is_su and self._dev_emu:
                    res = utils.do_shell_command(
                        'adb shell mount -o ro,remount /system')
                    if res is not None:
                        if res and 'not user mountable' in res:
                            # no root user
                            self._is_root = False
                        elif res == '':
                            # cmd executed fine
                            self._is_root = True
                        else:
                            # dont know some other output
                            self._is_root = False
                            print('rootcheck: %s' % res)

            if self._dev_emu:
                # get some infos about the device and keep for later
                self._sdk_version = self._do_adb_command(
                    'adb shell getprop ro.build.version.sdk')
                self._sdk_version = self._sdk_version.join(
                    self._sdk_version.split())  # cleans '\r\n'
                self._android_version = self._do_adb_command(
                    'adb shell getprop ro.build.version.release')
                self._android_version = self._android_version.join(
                    self._android_version.split())

                try:
                    self._oreo_plus = (int(
                        self._android_version.split('.')[0]) >= 8)
                except ValueError:
                    try:
                        self._oreo_plus = (int(self._sdk_version) > 25)
                    except ValueError:
                        pass

                # check if we have pidof
                if self._oreo_plus:
                    self._have_pidof = self._do_adb_command(
                        'adb shell pidof') == ''

                # fix some frida server problems
                # frida default port: 27042
                utils.do_shell_command('adb forward tcp:27042 tcp:27042')

    def get_states_string(self):
        """ Prints check results
        """
        ret_str = (
            'adb: {0}\ndev/emu: {1}\nsu: {2}\nroot: {3}\n\nat least 3x True required'
            .format(self._adb_available, self._dev_emu, self._is_su,
                    self._is_root))

        return ret_str

    def _do_adb_command(self, cmd, timeout=60):
        """ helper for calling adb
        """
        if not self.is_adb_available():
            return None

        res = utils.do_shell_command(cmd, timeout=timeout)
        if res is not None and 'no device' in res:
            return None

        return res

    def available(self):
        """ Returns True if adb and dev/emu and (su or root) is True
        """
        return self._adb_available and self._dev_emu and (self._is_root
                                                          or self._is_su)

    def get_device_arch(self):
        """ Returns value from ro.product.cpu.abi
        """
        if not self.is_adb_available():
            return None

        return self._do_adb_command('adb shell getprop ro.product.cpu.abi')

    def kill_frida(self):
        """ Kills frida on device
        """
        if not self.available():
            return False

        if self._oreo_plus:
            if self._have_pidof:
                procs = ['frida', 'frida-helper-32', 'frida-helper-64']
                for proc in procs:
                    pid = self.su_cmd('pidof %s' % proc)
                    self.su_cmd('kill -9 %s' % pid)
            else:
                self.su_cmd(
                    'kill -9 $(ps -A | grep \'frida\' | awk \'{ print $1 }\')')
        else:
            self.su_cmd(
                'kill -9 $(ps | grep \'frida\' | awk \'{ print $2 }\')')

        return True

    def start_frida(self, daemonize=True, restart=False):
        """ Starts/Restarts frida on device
        """
        if not self.available():
            return False

        if self.is_frida_running():
            if not restart:
                return True

            self.kill_frida()

        if not daemonize:
            result = self.su_cmd('frida &')
        else:
            # with nox it starts frida fine but keeps running
            # without return so it needs some timeout here
            result = self.su_cmd('frida -D', timeout=5)

        if result is not None and 'Unable to start server' in result:
            return False

        return True

    def is_adb_available(self):
        """ Returns true if adb cmd is available
        """
        return self._adb_available

    def is_frida_running(self):
        """ Checks if frida is running
        """
        if not self.available():
            return False

        found = False

        result = self.su_cmd('ps | grep \'frida\'')
        result = result.split()

        if 'frida' in result:
            for res in result:
                if 'frida-helper' in res:
                    found = True

        return found

    def get_frida_version(self):
        """ Returns version from 'frida --version'
        """
        if not self.available():
            return None

        result = self.su_cmd('frida --version')
        if result is not None:
            if result and 'frida: not found' in result:
                result = None

            if result == '':
                result = None

        if result is not None:
            return result.join(result.split())

        return None

    def kill_package(self, package):
        """ force-stop package
        """
        if not self.is_adb_available():
            return None

        return self._do_adb_command("adb shell am force-stop " + package)

    def list_packages(self):
        """ List packages on device
        """
        if not self.is_adb_available():
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
            _p = AndroidPackage()
            _p.path = needed[0] + '.apk'
            _p.package = needed[1]
            _p.package = _p.package.join(_p.package.split())
            ret.append(_p)
        return ret

    def package_path(self, package_name):
        """ Returns path on device from packagename
        """
        if not self.is_adb_available():
            return None

        _path = self._do_adb_command('adb shell pm path ' + package_name)
        if _path:
            try:
                _path = _path.join(_path.split())  # remove \r\n
                _path = _path.split(':')
                if len(_path) > 1 and _path[0] == 'package':
                    ret = _path[1]
                    if ret.endswith('apkpackage'):
                        # handle new android packages
                        ret = '/'.join(ret.split('/')[:-1])
                    return ret
            except ValueError:
                pass

        return None

    def mount_system(self):
        """ Mount System rw
        """
        if not self.available():
            return None

        return self.su_cmd('mount -o rw,remount /system')

    def install(self, path):
        """ Install apk
        """
        if not self.is_adb_available():
            return None

        if path:
            return self._do_adb_command('adb install %s' % path)

        return None

    def pull(self, path, dest):
        """ Pull from device
        """
        if not self.is_adb_available():
            return None

        if path and dest:
            return self._do_adb_command('adb pull %s %s' % (path, dest))

        return None

    def push(self, path, dest):
        """ Push to device
        """
        if not self.is_adb_available():
            return None

        return self._do_adb_command('adb push %s %s' % (path, dest))

    def su_cmd(self, cmd, timeout=60):
        """ Helper for calling root/su cmds
        """
        if not self.available():
            return None

        ret_val = None
        if self._is_su:
            ret_val = self._do_adb_command(
                'adb shell su -c "' + cmd + '"', timeout=timeout)
        elif self._is_root:
            ret_val = self._do_adb_command('adb shell ' + cmd, timeout=timeout)

        return ret_val
