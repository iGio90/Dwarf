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
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

import os
from PyQt5.QtCore import QObject
from dwarf_debugger.lib import utils
from dwarf_debugger.lib.android import AndroidPackage


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
        self._have_killall = False
        self._device_serial = None

        self._android_version = ''
        self._sdk_version = ''
        self._oreo_plus = False
        self._alternate_su_binary = False
        self._alternate_frida_name = False

        self._syspart_name = '/system'

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
            if adb_version:
                if adb_version and 'Android Debug Bridge' in adb_version:
                    self._adb_available = True
                else:
                    self._adb_available = False

            if self._adb_available:
                self._adb_available = False
                adb_devices = utils.do_shell_command('adb devices')

                try:
                    if adb_devices:
                        adb_devices = adb_devices.split(os.linesep)

                        for i, adb_device in enumerate(adb_devices):
                            if not adb_device: # skip empty lines at bottom
                                continue
                            if i == 0: # skip first line 'List of devices attached'
                                continue
                            if adb_device.startswith('*'): # skip these lines '* daemon started successfully *'
                                continue

                            self._adb_available = True

                    if not self._adb_available:
                        print('No Devices! Make sure \'Usb-Debugging\' is enabled in DeveloperSettings')

                except Exception as e:
                    print(e)

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
                    # if date was fine it should end with year
                    # Thu Feb 8 16:47:32 MST 2001
                    date_res = date_res.split(' ')
                    res_year = int(date_res[len(date_res) - 1])
                except ValueError:
                    return  # TODO: raise exceptions

            # try some su command to check for su binary
            res = self._do_adb_command('shell su -c date')
            if res and 'invalid' in res:
                res = self._do_adb_command('shell su 0 date')
                if res:
                    self._alternate_su_binary = True

            if res:
                try:
                    # if su date was fine it should end with year
                    # Thu Feb 8 16:47:32 MST 2001
                    su_res = res.split(' ')
                    res_year = int(su_res[len(su_res) - 1])
                    if res_year:
                        # su cmd is available
                        self._is_su = True

                        # check if both date results matches otherwise its no valid result
                        res_len = len(su_res)
                        date_len = len(date_res)
                        if su_res[res_len - 1] == date_res[date_len -
                                                           1]:  # year
                            if su_res[res_len - 2] == date_res[date_len -
                                                               2]:  # timezone
                                if su_res[res_len - 4] == date_res[date_len -
                                                                   4]:  # day
                                    if su_res[res_len - 5] == date_res[
                                            date_len - 5]:  # month
                                        self._is_root = True

                except ValueError:
                    pass

            res = self._do_adb_command('shell mount | grep system')
            if '/sbin/.magisk/block/system /' in res:
                self._syspart_name = '/sbin/.magisk/mirror/system'
            if '/system_root' in res:
                self._syspart_name = '/system_root'
                if '/sbin/.magisk/block/system_root /' in res:
                    self._syspart_name = '/sbin/.magisk/mirror/system_root'

            # check status of selinux
            res = self._do_adb_command('shell getenforce')
            if res:
                res = res.join(res.split())
                if res != 'Permissive' and res != 'Disabled':
                    self._do_adb_command('shell setenforce 0')

            # nox fix
            res = self.su_cmd('mount -o ro,remount ' + self._syspart_name)
            if res and 'invalid' in res:
                self._alternate_su_binary = True

            # no su -> try if the user is already root
            # on some emulators user is root
            if not self._is_su and self._dev_emu:
                res = self._do_adb_command('shell mount -o ro,remount ' + self._syspart_name)
                if res or res == '':
                    if res and 'not user mountable' in res:
                        # no root user
                        self._is_root = False
                    elif res == '':
                        # cmd executed fine
                        self._is_root = True
                    else:
                        # dont know some other output
                        self._is_root = False
                        # check for uid 0
                        res = self._do_adb_command('shell id')
                        # root should be 0
                        # https://superuser.com/questions/626843/does-the-root-account-always-have-uid-gid-0/626845#626845
                        self._is_root = 'uid=0' in res

            if self._dev_emu:
                # get some infos about the device and keep for later
                self._sdk_version = self._do_adb_command(
                    'shell getprop ro.build.version.sdk')
                if self._sdk_version:
                    self._sdk_version = self._sdk_version.join(
                        self._sdk_version.split())  # cleans '\r\n'
                self._android_version = self._do_adb_command(
                    'shell getprop ro.build.version.release')
                if self._android_version:
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
            res = self._do_adb_command('shell pidof -s pidof')
            self._have_pidof = 'not found' not in res
            res = self._do_adb_command('shell killall')
            self._have_killall = 'not found' not in res

            # check for correct userid
            if self._is_root:
                res = self.su_cmd('id')
                # root should be 0
                # https://superuser.com/questions/626843/does-the-root-account-always-have-uid-gid-0/626845#626845
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

        if res and 'no device' in res:
            return None

        return res

    def available(self):
        """ Returns True if adb and dev/emu and (su or root) is True
        """
        return self._adb_available and self._dev_emu and (self._is_root
                                                          or self._is_su)

    def non_root_available(self):
        """ Returns True if adb and dev/emu is True
        """
        return self._adb_available and self._dev_emu

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

        if self._have_killall:
            if self._alternate_frida_name:
                self.su_cmd('killall -9 frida-server')
            else:
                self.su_cmd('killall -9 frida')

        elif self._have_pidof:
            if self._alternate_frida_name:
                pid = self.su_cmd('pidof -s frida-server')
                if pid:
                    pid = pid.join(pid.split())  # remove \r\n
                    self.su_cmd('kill -9 %s' % pid)
            else:
                pid = self.su_cmd('pidof -s frida')
                if pid:
                    pid = pid.join(pid.split())  # remove \r\n
                    self.su_cmd('kill -9 %s' % pid)
        else:
            if self._oreo_plus:
                self.su_cmd(
                    'kill -9 $(ps -A | grep frida | awk \'{ print $1 }\')')
            else:
                self.su_cmd(
                    'kill -9 $(ps | grep frida | awk \'{ print $2 }\')')

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
            if self._alternate_frida_name:
                result = self.su_cmd('frida-server &')
            else:
                result = self.su_cmd('frida &')
        else:
            # with nox it starts frida fine but keeps running
            # without return so it needs some timeout here
            if self._alternate_frida_name:
                result = self.su_cmd('frida-server -D', timeout=5)
            else:
                result = self.su_cmd('frida -D', timeout=5)

        if result and 'Unable to start server' in result:
            return False

        return self.is_frida_running()

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
        pid = None

        if self._have_pidof:
            if self._alternate_frida_name:
                pid = self.su_cmd('pidof -s frida-server')
            else:
                pid = self.su_cmd('pidof -s frida')
            if pid:
                try:
                    pid = int(pid.join(pid.split()))  # remove \r\n
                    if pid:
                        return True
                except ValueError:
                    # no integer
                    pass

        if self._oreo_plus:
            result = self.su_cmd('ps -A | grep frida')
        else:
            result = self.su_cmd('ps | grep frida')

        if result:
            result = result.split()

            if 'frida' or 'frida-server' in result:
                found = True

        return found

    def get_frida_version(self):
        """ Returns version from 'frida --version'
        """
        if not self.available():
            return None

        result = self._do_adb_command('shell frida --version')
        if result:
            if 'not found' in result or 'No such file or directory' in result:
                result = self._do_adb_command('shell frida-server --version')
                if result and 'not found' in result:
                    return None
                elif result:
                    self._alternate_frida_name = True
        else:
            return None

        result = result.split(os.linesep)
        check_ver = result[len(result) - 2].replace('\r', '').split('.')
        if len(check_ver) == 3:
            try:
                v_major = int(check_ver[0])
                v_minor = int(check_ver[1])
                v_patch = int(check_ver[2])

                if v_major >= 12 and v_minor >= 8:
                    return '.'.join(check_ver)
                else:
                    print('frida version is outdated')
                    return '.'.join(check_ver)
            except ValueError:
                return None

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
        res = self.su_cmd('touch /system/.dwarf_check')
        if res == '':
            res = self._do_adb_command('shell ls -la /system')
            if '.dwarf_check' in res:
                res = self.su_cmd('rm /system/.dwarf_check')
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

        res = self.su_cmd('mount -o rw,remount ' + self._syspart_name)

        if res == '':
            is_mounted = self._check_mounted_system()
        else:
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
                    'shell su 0 ' + cmd, timeout=timeout)
            else:
                ret_val = self._do_adb_command(
                    'shell su -c ' + cmd, timeout=timeout)
                
                if ret_val and 'Unknown id:' in ret_val:
                    self._alternate_su_binary = True
                    return self.su_cmd(cmd, timeout)

                if ret_val and 'su: invalid option' in ret_val:
                    ret_val = self._do_adb_command(
                        'shell su -c "' + cmd + '"', timeout=timeout)

        elif self._is_root:
            ret_val = self._do_adb_command('shell ' + cmd, timeout=timeout)

        return ret_val
