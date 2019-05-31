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
        self._device_serial = None

        self._android_version = ''
        self._sdk_version = ''
        self._oreo_plus = False
        self._alternate_su_binary = False

        self._check_min_required()

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def device(self):
        """ return device_serial
        """
        return self._device_serial

    @device.setter
    def device(self, value):
        """ set serial and check for root
        """
        try:
            if isinstance(value, str):
                self._device_serial = value
                self._check_requirements()
        except ValueError:
            self._device_serial = None

    @property
    def min_required(self):
        """ return if adb cmd is available
            checked in init
        """
        return self._adb_available

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def _check_min_required(self):
        """ Checks if adb is available
        """
        self._adb_available = False
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

    def _check_requirements(self):  # pylint: disable=too-many-branches, too-many-statements
        """ Checks root on device
        """
        self._dev_emu = False
        self._is_root = False
        self._is_su = False
        self._alternate_su_binary = False

        if not self._device_serial:
            return

        if self._adb_available:
            # try some command
            date_res = self._do_adb_command('shell date')
            # adb not authorized
            if date_res and 'device unauthorized' in date_res:
                # kill adb daemon
                utils.do_shell_command('adb kill-server')
                utils.show_message_box(
                    'device not authorized! allow access from this computer on the device'
                )

            if date_res and 'no devices/emulators' in date_res:
                self._dev_emu = False
                return
            elif date_res and 'device not found' in date_res:
                self._dev_emu = False
                return
            else:
                self._dev_emu = True

            if self._dev_emu and date_res:
                try:
                    date_res = date_res.split(' ')
                except ValueError:
                    pass

            # try some su command
            res = self._do_adb_command('shell su -c date')
            if res and 'Permission denied' in res:
                self._is_su = False
            elif res and 'su: not found' in res:
                self._is_su = False
            elif res and 'invalid' in res:
                res = self._do_adb_command('shell su 0 date')
                if res:
                    self._alternate_su_binary = True

            if res is not None:
                try:
                    res = res.split(' ')
                except ValueError:
                    pass

                # check if 'same' results otherwise its no valid result from su -c date
                if len(res) == len(date_res):
                    if res[len(res) - 1] == date_res[len(date_res) - 1]:
                        if res[len(res) - 2] == date_res[len(date_res) - 2]:
                            self._is_su = True

                # no su -> try if the user is already root
                # on some emulators user is root
                if not self._is_su and self._dev_emu:
                    res = self._do_adb_command(
                        'shell mount -o ro,remount /system')
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
                    'shell getprop ro.build.version.sdk')
                if self._sdk_version is not None:
                    self._sdk_version = self._sdk_version.join(
                        self._sdk_version.split())  # cleans '\r\n'
                self._android_version = self._do_adb_command(
                    'shell getprop ro.build.version.release')
                if self._android_version is not None:
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

                # fix some frida server problems
                # frida default port: 27042
                utils.do_shell_command('adb forward tcp:27042 tcp:27042')

            # check if we have pidof
            if self._oreo_plus:
                res = self._do_adb_command('shell pidof')
                self._have_pidof = 'not found' not in res

            # check for root
            if self._is_root:
                res = self.su_cmd('id')
                self._is_root = 'uid=0' in res

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

        # TODO: for android sdk emulator its using -e
        res = utils.do_shell_command(
            'adb -s ' + self._device_serial + ' ' + cmd, timeout=timeout)

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

        return self._do_adb_command('shell getprop ro.product.cpu.abi')

    def kill_frida(self):
        """ Kills frida on device
        """
        if not self.available():
            return False

        if self._have_pidof:
            procs = ['frida']  #, 'frida-helper-32', 'frida-helper-64']
            for proc in procs:
                pid = self.su_cmd('pidof %s' % proc)
                if pid:
                    pid = pid.join(pid.split())
                    self.su_cmd('kill -9 %s' % pid)
        else:
            if self._oreo_plus:
                self.su_cmd(
                    'kill -9 $(ps -A | grep \'frida\' | awk \'{ print $1 }\')')
            else:
                self.su_cmd(
                    'kill -9 $(ps | grep \'frida\' | awk \'{ print $2 }\')')

        return not self.is_frida_running()

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

        if self._have_pidof:
            pid = self.su_cmd('pidof frida')
            if pid:
                try:
                    pid = int(pid.join(pid.split())) # remove \r\n
                except ValueError:
                    # no integer
                    return False

                return True

        if self._oreo_plus:
            result = self.su_cmd('ps -A | grep \'frida\'')
        else:
            result = self.su_cmd('ps | grep \'frida\'')

        if result is not None:
            result = result.split()

            if 'frida' in result:
                # in frida 12.5.0 there was no frida-helper on my tested devs TODO: Recheck
                # for res in result:
                # if 'frida-helper' in res:
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

        return self._do_adb_command("shell am force-stop " + package)

    def list_packages(self):
        """ List packages on device
        """
        if not self.is_adb_available():
            return None

        packages = self._do_adb_command('shell pm list packages -f')
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

        _path = self._do_adb_command('shell pm path ' + package_name)
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

    def _check_mounted_system(self):
        """ check if we can write to /system
        """
        res = self._do_adb_command('shell touch /system/.dwarf_check')
        if res == '':
            res = self._do_adb_command('shell ls -la /system')
            if '.dwarf_check' in res:
                res = self._do_adb_command('shell rm /system/.dwarf_check')
                if res == '':
                    return True
        elif res == 'Read-only file system':
            return False

        return False

    def mount_system(self):
        """ Mount System rw
        """
        is_mounted = False
        if not self.available():
            return None

        res = self.su_cmd('mount -o rw,remount /system')
        if '/system' and '/proc/mounts' in res:
            res = self._do_adb_command('shell mount | grep system')
            if res is '':
                res = self.su_cmd('mount -o rw,remount /')
                if res == '':
                    if self._check_mounted_system():
                        is_mounted = True
                    else:
                        # try if androidsdk emu
                        # adb root on real dev -> 'is not allowed to run as root in production builds'
                        res = self._do_adb_command('root')
                        res = self._do_adb_command('remount')
                        if res == 'remount succeeded':
                            is_mounted = self._check_mounted_system()
                        else:
                            is_mounted = False

        elif res == '':
            is_mounted = self._check_mounted_system()

        return is_mounted

    def install(self, path):
        """ Install apk
        """
        if not self.is_adb_available():
            return None

        if path:
            return self._do_adb_command('install %s' % path)

        return None

    def pull(self, path, dest):
        """ Pull from device
        """
        if not self.is_adb_available():
            return None

        if path and dest:
            return self._do_adb_command('pull %s %s' % (path, dest))

        return None

    def push(self, path, dest):
        """ Push to device
        """
        if not self.is_adb_available():
            return None

        return self._do_adb_command('push %s %s' % (path, dest))

    def su_cmd(self, cmd, timeout=60):
        """ Helper for calling root/su cmds
        """
        if not self.available():
            return None

        ret_val = None
        if self._is_su:
            if self._alternate_su_binary:
                ret_val = self._do_adb_command(
                    'shell su 0 "' + cmd + '"', timeout=timeout)
            else:
                ret_val = self._do_adb_command(
                    'shell su -c "' + cmd + '"', timeout=timeout)
        elif self._is_root:
            ret_val = self._do_adb_command('shell ' + cmd, timeout=timeout)

        return ret_val
