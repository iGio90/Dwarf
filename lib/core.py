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
import numbers
import binascii
import json
from threading import Thread

from frida.core import Session, Device, Script

import frida
from PyQt5.QtCore import QObject, pyqtSignal, QThread
from PyQt5.QtWidgets import QFileDialog, QApplication
from ui.hex_edit import HighLight, HighlightExistsError

from lib import utils
from lib.context import Context
from lib.emulator import Emulator

from lib.hook import Hook
from lib.kernel import Kernel
from lib.prefs import Prefs

from ui.dialog_input import InputDialog
from ui.panel_trace import TraceEvent


class EmulatorThread(QThread):

    onCmdCompleted = pyqtSignal(str, name='onCmdCompleted')
    onError = pyqtSignal(str, name='onError')

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.emulator = None
        self.cmd = ''

    def run(self):
        if self.emulator and self.cmd:
            try:
                result = self.emulator.api(self.cmd)
                self.onCmdCompleted.emit(str(result))
            except Emulator.EmulatorSetupFailedError as error:
                result = False
                self.onError.emit(error)
            except Emulator.EmulatorAlreadyRunningError as error:
                result = False
                self.onError.emit(error)


class Dwarf(QObject):
    class NoDeviceAssignedError(Exception):
        """ Raised when no Device
        """

    class CoreScriptNotFoundError(Exception):
        """ Raised when dwarfscript not found
        """

    # ************************************************************************
    # **************************** Signals ***********************************
    # ************************************************************************
    # script related
    onScriptLoaded = pyqtSignal(name='onScriptLoaded')
    onScriptDestroyed = pyqtSignal(name='onScriptDestroyed')
    onAttached = pyqtSignal(list, name='onAttached')
    # hook related
    onAddNativeHook = pyqtSignal(Hook, name='onAddNativeHook')
    onAddJavaHook = pyqtSignal(Hook, name='onAddJavaHook')
    onAddOnLoadHook = pyqtSignal(Hook, name='onAddOnLoadHook')
    # watcher related
    onWatcherAdded = pyqtSignal(str, int, name='onWatcherAdded')
    onWatcherRemoved = pyqtSignal(str, name='onWatcherRemoved')
    # ranges + modules
    onSetRanges = pyqtSignal(list, name='onSetRanges')
    onSetModules = pyqtSignal(list, name='onSetModules')
    onHitOnLoad = pyqtSignal(list, name='onHitOnLoad')
    onLogToConsole = pyqtSignal(str, name='onLogToConsole')
    # thread+context
    onThreadResumed = pyqtSignal(int, name='onThreadResumed')
    onApplyContext = pyqtSignal(dict, name='onApplyContext')
    # java
    onEnumerateJavaClassesStart = pyqtSignal(name='onEnumerateJavaClassesStart')
    onEnumerateJavaClassesMatch = pyqtSignal(str, name='onEnumerateJavaClassesMatch')
    onEnumerateJavaClassesComplete = pyqtSignal(name='onEnumerateJavaClassesComplete')
    onEnumerateJavaMethodsComplete = pyqtSignal(list, name='onEnumerateJavaMethodsComplete')
    # memory
    onMemoryScanComplete = pyqtSignal(list, name='onMemoryScanComplete')
    onMemoryScanMatch = pyqtSignal(list, name='onMemoryScanMatch')
    # trace
    onJavaTraceEvent = pyqtSignal(list, name='onJavaTraceEvent')
    onTraceData = pyqtSignal(str, name='onTraceData')
    onSetData = pyqtSignal(list, name='onSetData')
    # emulator
    onEmulator = pyqtSignal(list, name='onEmulator')

    # ************************************************************************
    # **************************** Init **************************************
    # ************************************************************************
    def __init__(self, session=None, parent=None, device=None):
        super(Dwarf, self).__init__(parent=parent)

        self._app_window = parent

        self.java_available = False
        self._loading_library = False

        # frida device
        self._device = device

        # process
        self._pid = 0
        self._process = None
        self._script = None
        self._spawned = False
        self._resumed = False

        # kernel
        self._kernel = Kernel(self)

        self._watchers = []

        # hooks
        self.hooks = {}
        self.on_loads = {}
        self.java_hooks = {}
        self.temporary_input = ''
        self.native_pending_args = None
        self.java_pending_args = None

        # context
        self._arch = ''
        self._pointer_size = 0
        self.contexts = {}
        self.context_tid = 0
        self._platform = ''
        self.loading_library = None

        # tracers
        self._native_traced_tid = 0

        # emulator stuff
        self._emulator = Emulator(self)
        self._emu_thread = EmulatorThread(self)
        self._emu_thread.onCmdCompleted.connect(self._on_emu_completed)
        self._emu_thread.onError.connect(self._on_emu_error)
        self._emu_thread.emulator = self.emulator
        self._emu_queue = []

        # connect to self
        self.onApplyContext.connect(self._on_apply_context)
        self.onEmulator.connect(self._on_emulator)

        self.keystone_installed = False
        try:
            import keystone.keystone_const
            self.keystone_installed = True
        except:
            pass

    def _reinitialize(self):
        self.java_available = False
        self._loading_library = False
        self.loading_library = None

        # frida device
        self._device = None

        # process
        self._process = None
        self._script = None

        # hooks
        self.hooks = {}
        self.on_loads = {}
        self.java_hooks = {}
        self.temporary_input = ''
        self.native_pending_args = None
        self.java_pending_args = None

        # tracers
        self._native_traced_tid = 0

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def kernel(self):
        return self._kernel

    @property
    def emulator(self):
        return self._emulator

    @property
    def loading_library(self):
        return self._loading_library

    @property
    def native_trace_tid(self):
        return self._native_traced_tid

    @property
    def arch(self):
        return self._arch

    @property
    def pid(self):
        return self._pid

    @property
    def platform(self):
        return self._platform

    @property
    def pointer_size(self):
        return self._pointer_size

    @property
    def process(self):
        return self._process

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, value):
        try:
            if isinstance(value, frida.core.Device):
                self._device = value
        except ValueError:
            self._device = None

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************

    def is_address_watched(self, ptr):
        ptr = utils.parse_ptr(ptr)
        if ptr in self._watchers:
            return True

        return False

    def attach(self, pid, script=None, print_debug_error=True):
        """ Attach to pid
        """
        if self.device is None:
            raise self.NoDeviceAssignedError('No Device assigned')

        if self._process is not None:
            self.detach()

        was_error = False
        error_msg = ''

        # for commandline arg
        if isinstance(pid, str):
            try:
                process = self.device.get_process(pid)
                pid = [process.pid, process.name]
            except frida.ProcessNotFoundError as error:
                print(error)
                return 2

        if not isinstance(pid, list):
            return 1

        try:
            self._process = self.device.attach(pid[0])
            self._process.enable_jit()
            self._pid = pid[0]
        except frida.ProcessNotFoundError:
            error_msg = 'Process not found'
            was_error = True
        except frida.ProcessNotRespondingError:
            error_msg = 'Process not responding'
            was_error = True
        except frida.TimedOutError:
            error_msg = 'Frida timeout'
            was_error = True
        except frida.ServerNotRunningError:
            error_msg = 'Frida not running'
            was_error = True
        # keep for debug
        except Exception as error:  # pylint: disable=broad-except
            error_msg = error
            was_error = True

        if was_error:
            if print_debug_error:
                utils.show_message_box('Failed to attach to ' + pid[1], error_msg)

            return 2

        self.onAttached.emit([self.pid, pid[1]])
        self.load_script(script)
        return 0

    def detach(self):
        if self._script is not None:
            self.dwarf_api('_detach')
            self._script.unload()
        if self._process is not None:
            self._process.detach()
            if self._spawned:
                self.device.kill(self.pid)

    def load_script(self, script=None):
        try:
            if not os.path.exists('lib/core.js'):
                raise self.CoreScriptNotFoundError('core.js not found!')

            with open('lib/core.js', 'r') as core_script:
                sript_content = core_script.read()
            self._script = self._process.create_script(sript_content)
            self._script.on('message', self._on_message)
            self._script.on('destroyed', self._on_destroyed)
            self._script.load()

            if script is not None:
                if os.path.exists(script):
                    with open(script, 'r') as script_file:
                        user_script = script_file.read()

                    self.dwarf_api('evaluateFunction', user_script)

            self.onScriptLoaded.emit()
        except frida.TimedOutError:
            print('frida timeout')
            self._on_destroyed()
        except frida.TransportError:
            print('frida transporterror')
            self._on_destroyed()

    def spawn(self, package, script=None):
        if self.device is None:
            raise self.NoDeviceAssignedError('No Device assigned')

        if self._process is not None:
            self.detach()

        try:
            self._pid = self.device.spawn(package)
            self._process = self.device.attach(self._pid)
            self._process.enable_jit()
            self._spawned = True
        except Exception as e:
            utils.show_message_box('Failed to spawn to %s' % package, str(e))
            return 2
        self.onAttached.emit([self.pid, package])
        self.load_script(script)
        return 0

    def resume_proc(self):
        if self._spawned:
            self._resumed = True
            self.device.resume(self._pid)

    def add_watcher(self, ptr=None):
        if ptr is None:
            ptr, input = InputDialog.input_pointer(self._app_window)
            if ptr == 0:
                return
        return self.dwarf_api('addWatcher', ptr)

    def dump_memory(self, file_path=None, ptr=0, length=0):
        if ptr == 0:
            ptr, inp = InputDialog.input_pointer(self._app_window)
        if ptr > 0:
            if length == 0:
                accept, length = InputDialog.input(
                    self._app_window, hint='insert length', placeholder='1024')
                if not accept:
                    return
                try:
                    if length.startswith('0x'):
                        length = int(length, 16)
                    else:
                        length = int(length)
                except:
                    return
            if file_path is None:
                r = QFileDialog.getSaveFileName(self._app_window, caption='Save binary dump to file')
                if len(r) == 0 or len(r[0]) == 0:
                    return
                file_path = r[0]
            data = self.read_memory(ptr, length)
            with open(file_path, 'wb') as f:
                f.write(data)

    def dwarf_api(self, api, args=None, tid=0):
        if self.pid == 0 or self.process is None:
            return
        if tid == 0:
            tid = self.context_tid
        if args is not None and not isinstance(args, list):
            args = [args]
        if self._script is None:
            return None
        try:
            return self._script.exports.api(tid, api, args)
        except Exception as e:
            self.log(str(e))
            return None

    def hook_java(self, input_=None, pending_args=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(
                self._app_window, hint='insert java class or methos',
                placeholder='com.package.class or com.package.class.method')
            if not accept:
                return
        self.java_pending_args = pending_args
        input_ = input_.replace(' ', '')
        self.dwarf_api('hookJava', input_)

    def hook_native(self, input_=None, pending_args=None, own_input=None):
        if input_ is None or not isinstance(input_, str):
            ptr, input_ = InputDialog.input_pointer(self._app_window)
        else:
            ptr = utils.parse_ptr(self._app_window.dwarf.dwarf_api('evaluatePtr', input_))
        if ptr > 0:
            self.temporary_input = input_
            if own_input is not None:
                self.temporary_input = own_input
            self.native_pending_args = pending_args
            self.dwarf_api('hookNative', ptr)

    def hook_onload(self, input_=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(self._app_window, hint='insert module name', placeholder='libtarget.so')
            if not accept:
                return
            if len(input_) == 0:
                return

        if input_ in self._app_window.dwarf.on_loads:
            return

        self.dwarf_api('hookOnLoad', input_)

    def log(self, what):
        self.onLogToConsole.emit(str(what))

    def native_tracer_start(self, tid=0):
        if self.native_traced_tid > 0:
            return
        if tid == 0:
            accept, tid = InputDialog.input(self._app_window, hint='insert thread id to trace', placeholder=str(self.pid))
            if not accept:
                return
            try:
                if tid.startswith('0x'):
                    tid = int(tid, 16)
                else:
                    tid = int(tid)
            except:
                return
        self.native_traced_tid = tid
        return self.dwarf_api('startNativeTracer', [tid, True])

    def native_tracer_stop(self):
        if self.native_traced_tid == 0:
            return
        self.dwarf_api('stopNativeTracer')
        if self._app_window.trace_panel is not None:
            self._app_window.trace_panel.stop()
        self.native_traced_tid = 0
        # self._app_window.get_menu().on_native_tracer_change(False)

    def read_memory(self, ptr, length):
        if length > 1024 * 1024:
            position = 0
            next_size = 1024 * 1024
            data = bytearray()
            while True:
                try:
                    data += self.dwarf_api('readBytes', [ptr + position, next_size])
                except:
                    return None
                position += next_size
                diff = length - position
                if diff > 1024 * 1024:
                    next_size = 1024 * 1024
                elif diff > 0:
                    next_size = diff
                else:
                    break
            ret = bytes(data)
            del data
            return ret
        else:
            return self.dwarf_api('readBytes', [ptr, length])

    def remove_watcher(self, ptr):
        return self.dwarf_api('removeWatcher', ptr)

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_message(self, message, data):
        QApplication.processEvents()
        if 'payload' not in message:
            print('payload: ' + str(message))
            return

        what = message['payload']
        parts = what.split(':::')
        if len(parts) < 2:
            print(what)
            return

        cmd = parts[0]
        if cmd == 'backtrace':
            try:
                self._app_window.backtrace_panel.set_backtrace(json.loads(parts[1]))
            except:
                pass
        elif cmd == 'emulator':
            self.onEmulator.emit(parts[1:])
        elif cmd == 'enumerate_java_classes_start':
            self.onEnumerateJavaClassesStart.emit()
        elif cmd == 'enumerate_java_classes_match':
            self.onEnumerateJavaClassesMatch.emit(parts[1])
        elif cmd == 'enumerate_java_classes_complete':
            self.onEnumerateJavaClassesComplete.emit()
        elif cmd == 'enumerate_java_methods_complete':
            self.onEnumerateJavaMethodsComplete.emit([parts[1], json.loads(parts[2])])
        elif cmd == 'ftrace':
            if self.app.get_ftrace_panel() is not None:
                self.app.get_ftrace_panel().append_data(parts[1])
        elif cmd == 'enable_kernel':
            self._app_window.get_menu().enable_kernel_menu()
        elif cmd == 'hook_java_callback':
            h = Hook(Hook.HOOK_JAVA)
            h.set_ptr(1)
            h.set_input(parts[1])
            if self.java_pending_args:
                h.set_condition(self.java_pending_args['condition'])
                h.set_logic(self.java_pending_args['logic'])
                self.java_pending_args = None
            self.java_hooks[h.get_input()] = h
            self.onAddJavaHook.emit(h)
        elif cmd == 'hook_native_callback':
            h = Hook(Hook.HOOK_NATIVE)
            h.set_ptr(int(parts[1], 16))
            h.set_input(self.temporary_input)
            h.set_bytes(binascii.unhexlify(parts[2]))
            self.temporary_input = ''
            h.set_condition(parts[4])
            h.set_logic(parts[3])
            self.native_pending_args = None
            self.hooks[h.get_ptr()] = h
            self.onAddNativeHook.emit(h)
        elif cmd == 'hook_onload_callback':
            h = Hook(Hook.HOOK_ONLOAD)
            h.set_ptr(0)
            h.set_input(parts[1])
            self.on_loads[parts[1]] = h
            self.onAddOnLoadHook.emit(h)
        elif cmd == 'java_trace':
            self.onJavaTraceEvent.emit(parts)
        elif cmd == 'log':
            self.log(parts[1])
        elif cmd == 'memory_scan_match':
            self.onMemoryScanMatch.emit([parts[1], parts[2], json.loads(parts[3])])
        elif cmd == 'memory_scan_complete':
            self._app_window.get_menu().on_bytes_search_complete()
            self.onMemoryScanComplete.emit([parts[1] + ' complete', 0, 0])
        elif cmd == 'onload_callback':
            self.loading_library = parts[1]
            str_fmt = ('Hook onload {0} @thread := {1}'.format(parts[1], parts[3]))
            self.log(str_fmt)
            self.onHitOnLoad.emit([parts[1], parts[2]])
        elif cmd == 'release':
            if parts[1] in self.contexts:
                del self.contexts[parts[1]]
            self.onThreadResumed.emit(int(parts[1]))
        elif cmd == 'set_context':
            data = json.loads(parts[1])
            if 'modules' in data:
                self.onSetModules.emit(data['modules'])
            if 'ranges' in data:
                self.onSetRanges.emit(data['ranges'])

            self.onApplyContext.emit(data)
        elif cmd == 'set_data':
            if data:
                self.onSetData.emit(['raw', parts[1], data])
            else:
                self.onSetData.emit(['plain', parts[1], str(parts[2])])
        elif cmd == 'tracer':
            self.onTraceData.emit(parts[1])
        elif cmd == 'unhandled_exception':
            # todo
            pass
        elif cmd == 'update_modules':
            modules = json.loads(parts[2])
            # todo update onloads bases
            self.onSetModules.emit(modules)
        elif cmd == 'update_ranges':
            self.onSetRanges.emit(json.loads(parts[2]))
        elif cmd == 'watcher':
            exception = json.loads(parts[1])
            self.log('watcher hit op %s address %s @thread := %s' %
                     (exception['memory']['operation'], exception['memory']['address'], parts[2]))
        elif cmd == 'watcher_added':
            self._watchers.append(utils.parse_ptr(parts[1]))
            self.onWatcherAdded.emit(parts[1], int(parts[2]))
        elif cmd == 'watcher_removed':
            self._watchers.remove(utils.parse_ptr(parts[1]))
            self.onWatcherRemoved.emit(parts[1])
        else:
            print('unknown message: ' + what)

    def _on_apply_context(self, context_data):
        if 'context' in context_data:
            context = Context(context_data['context'])
            self.contexts[str(context_data['tid'])] = context

            sym = ''
            if 'pc' in context_data['context']:
                name = context_data['ptr']
                if context_data['context']['pc']['symbol']['name'] is not None:
                    sym = context_data['context']['pc']['symbol']['moduleName']
                    sym += ' - '
                    sym += context_data['context']['pc']['symbol']['name']
            else:
                name = context_data['ptr']
            self._app_window.threads.add_context(context_data, library_onload=self.loading_library)
            if self.loading_library is None and context_data['reason'] == 0:
                self.log('hook %s %s @thread := %d' % (name, sym, context_data['tid']))
            # if len(self.contexts.keys()) > 1 and self._app_window.context_panel.have_context():
            #    return
        else:
            self._arch = context_data['arch']
            self._platform = context_data['platform']
            self._pointer_size = context_data['pointerSize']
            self.java_available = context_data['java']
            str_fmt = ('injected into := {0:d}'.format(self.pid))
            self.log(str_fmt)

        self.context_tid = context_data['tid']
        if self._loading_library is not None:
            self._loading_library = None

    def _on_destroyed(self):
        self._reinitialize()
        str_fmt = ('Detached from {0:d}. Script destroyed.'.format(self.pid))
        self.log(str_fmt)
        self.onScriptDestroyed.emit()

    def _on_emulator(self, data):
        if not self._app_window.emulator_panel:
            self._app_window._create_ui_elem('emulator')
            self._app_window.show_main_tab('emulator')

        if self.emulator and self._emu_thread:
            if not self._emu_thread.isRunning():
                self._emu_thread.cmd = data
                self._emu_thread.start()
            else:
                self._emu_queue.append(data)

    def _on_emu_completed(self, result):
        self.log(result)  # todo: send back to script???
        if self._emu_queue:
            self._emu_thread.cmd = self._emu_queue[0]
            self._emu_queue = self._emu_queue[1:]
            self._emu_thread.start()
        else:
            self._emu_thread.cmd = ''

    def _on_emu_error(self, err_str):
        self.log(err_str)
        if self._emu_queue:
            self._emu_queue.clear()

    @loading_library.setter
    def loading_library(self, value):
        self._loading_library = value
