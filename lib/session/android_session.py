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

import frida
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QMenu, QAction, QFileDialog

from lib.session.session import Session
from lib.android import AndroidDecompileUtil
from lib.adb import Adb

from ui.device_window import DeviceWindow
from ui.widgets.apk_list import ApkListDialog
from lib import utils


class SmaliThread(QThread):
    onFinished = pyqtSignal(name='onFinished')
    onError = pyqtSignal(name='onError')

    def __init__(self, parent=None, device_id=None, package_name=None):
        super(SmaliThread, self).__init__(parent)
        self._adb = Adb()
        self._adb.device = device_id
        self._package_name = package_name

    def run(self):
        if self._adb.device is None:
            return

        if not self._package_name:
            self.onError.emit()
            return

        _path = self._adb.package_path(self._package_name)
        if not os.path.exists('.tmp'):
            os.mkdir('.tmp')

        if _path:
            self._adb.pull(_path, '.tmp/base.apk')
            if os.path.exists('.tmp/base.apk'):
                _baksmali_cmd = 'd2j-baksmali.sh'
                if os.name == 'nt':
                    _baksmali_cmd = _baksmali_cmd.replace('.sh', '.bat')
                try:
                    utils.do_shell_command(_baksmali_cmd + ' .tmp/base.apk -o .tmp/smali')
                    self.onFinished.emit()
                except:
                    # no d2j
                    self.onError.emit()
        else:
            self.onError.emit()


class AndroidSession(Session):
    """ All Android Stuff goes here
        if u look for something android related its here then
    """

    def __init__(self, app_window):
        super(AndroidSession, self).__init__(app_window)
        self.adb = Adb()

        if not self.adb.min_required:
            utils.show_message_box(self.adb.get_states_string())

        if app_window.dwarf_args.package is None:
            self._device_window = DeviceWindow(self._app_window, 'usb')

        self._smali_thread = None

    @property
    def session_ui_sections(self):
        # what sections we want in session_ui
        return ['hooks', 'bookmarks', 'threads', 'registers', 'debug', 'console',
                'watchers', 'modules', 'jvm-inspector', 'jvm-debugger',
                'ranges', 'backtrace']

    @property
    def non_closable(self):
        return ['debug', 'ranges', 'modules', 'jvm-inspector', 'jvm-debugger']

    @property
    def session_type(self):
        """ return session name to show in menus etc
        """
        return 'Android'

    def _setup_menu(self):
        """ Build Menus
        """
        # additional menus
        file_menu = QMenu('&Device')
        save_apk = QAction("&Save APK", self)
        save_apk.triggered.connect(self.save_apk)
        decompile_apk = QAction("&Decompile APK", self)
        decompile_apk.triggered.connect(self.decompile_apk)

        file_menu.addAction(save_apk)
        file_menu.addAction(decompile_apk)

        self._menu.append(file_menu)

        super()._setup_menu()

        java_menu = QMenu('&Java')
        java_menu.addAction('Trace', self._on_java_trace)
        java_menu.addSeparator()
        java_menu.addAction('Classes', self._on_java_classes)
        self._menu.append(java_menu)

    def stop_session(self):
        # cleanup ur stuff

        # end session
        super().stop()

    def start(self, args):
        self.dwarf.onScriptDestroyed.connect(self.stop)
        if args.package is None:
            self._device_window.setModal(True)
            self._device_window.onSelectedProcess.connect(self.on_proc_selected)
            self._device_window.onSpwanSelected.connect(self.on_spawn_selected)
            self._device_window.onClosed.connect(self._on_devdlg_closed)
            self._device_window.show()
        else:
            if not args.device:
                self.dwarf.device = frida.get_usb_device()
            else:
                self.adb.device = args.device
                self.dwarf.device = frida.get_device(id=args.device)
            if not args.spawn:
                print('* Trying to attach to {0}'.format(args.package))
                try:
                    self.dwarf.attach(args.package, args.script, False)
                except Exception as e:  # pylint: disable=broad-except
                    print('Reason: ' + str(e))
                    print('Help: you can use -sp to force spawn')
                    self.stop()
                    exit(0)
            else:
                print('* Trying to spawn {0}'.format(args.package))
                try:
                    self.dwarf.spawn(args.package, args.script)
                except Exception as e:  # pylint: disable=broad-except
                    print('Reason: ' + str(e))
                    self.stop()
                    exit(0)

    def decompile_apk(self):
        apk_dlg = ApkListDialog(self._app_window)
        apk_dlg.onApkSelected.connect(self._decompile_package)
        apk_dlg.show()

    def _decompile_package(self, data):
        package, path = data
        if path is not None:
            # todo: make qthread
            AndroidDecompileUtil.decompile(self.adb, path)

    def save_apk(self):
        apk_dlg = ApkListDialog(self._app_window)
        apk_dlg.onApkSelected.connect(self._save_package)
        apk_dlg.show()

    def _save_package(self, data):
        package, path = data
        if path is not None:
            result = QFileDialog.getSaveFileName(caption='Location to save ' + package,
                                                 directory='./' + package + '.apk', filter='*.apk')
            if result and result[0]:
                self.adb.pull(path, result[0])

    def on_proc_selected(self, data):
        device, pid = data
        if device:
            self.adb.device = device.id
            self.dwarf.device = device
        if pid:
            try:
                self.dwarf.attach(pid)
            except Exception as e:
                utils.show_message_box('Failed attaching to {0}'.format(pid), str(e))
                self.stop()
                return

    def on_spawn_selected(self, data):
        device, package_name, break_at_start = data
        if device:
            self.adb.device = device.id
            self.dwarf.device = device
        if package_name:
            # smalistuff
            if self._smali_thread is None:
                self._app_window.show_progress('Baksmali ' + package_name + ' ...')
                self._smali_thread = SmaliThread(self, device.id, package_name)
                self._smali_thread.onError.connect(self._app_window.hide_progress)
                self._smali_thread.onFinished.connect(self._app_window.hide_progress)
                self._smali_thread.start()

            try:
                self.dwarf.spawn(package=package_name, break_at_start=break_at_start)
            except Exception as e:
                utils.show_message_box('Failed spawning {0}'.format(package_name), str(e))
                self.stop()
                return

            self._on_java_classes()

    def _on_java_trace(self):
        tag = 'jvm-tracer'
        should_request_classes = \
            self._app_window.java_trace_panel is None or tag not in self._app_window.ui_elements
        self._app_window.show_main_tab(tag)
        if should_request_classes:
            self.dwarf.dwarf_api('enumerateJavaClasses')

    def _on_java_classes(self):
        self._app_window.show_main_tab('jvm-inspector')
        self.dwarf.dwarf_api('enumerateJavaClasses')

    def _on_devdlg_closed(self):
        if self.dwarf.device is None:
            self.stop_session()
