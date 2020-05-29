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

import frida
import json

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QFileDialog, QApplication
from dwarf_debugger.lib.types.module_info import ModuleInfo

from frida.core import Session

from dwarf_debugger.lib import utils
from dwarf_debugger.lib.context import Context
from dwarf_debugger.lib.database import Database
from dwarf_debugger.lib.disassembler import Disassembler
from dwarf_debugger.lib.types.breakpoint import Breakpoint, BREAKPOINT_NATIVE, BREAKPOINT_JAVA, BREAKPOINT_INITIALIZATION, BREAKPOINT_OBJC
from dwarf_debugger.lib.types.watchpoint import Watchpoint
from dwarf_debugger.lib.io import IO
from dwarf_debugger.lib.kernel import Kernel

from dwarf_debugger.ui.dialogs.dialog_input import InputDialog


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
    # process
    onProcessDetached = pyqtSignal(list, name='onProcessDetached')
    onProcessAttached = pyqtSignal(list, name='onProcessAttached')
    # script related
    onScriptLoaded = pyqtSignal(name='onScriptLoaded')
    onScriptDestroyed = pyqtSignal(name='onScriptDestroyed')
    # breakpoint related
    onAddNativeBreakpoint = pyqtSignal(Breakpoint, name='onAddNativeBreakpoint')
    onAddJavaBreakpoint = pyqtSignal(Breakpoint, name='onAddJavaBreakpoint')
    onAddObjCBreakpoint = pyqtSignal(Breakpoint, name='onAddObjCBreakpoint')
    onAddModuleInitializationBreakpoint = pyqtSignal(Breakpoint, name='onAddModuleInitializationBreakpoint')
    onAddJavaClassInitializationBreakpoint = pyqtSignal(Breakpoint, name='onAddJavaClassInitializationBreakpoint')
    onDeleteBreakpoint = pyqtSignal(list, name='onDeleteBreakpoint')
    onHitModuleInitializationBreakpoint = pyqtSignal(list, name='onHitModuleInitializationBreakpoint')
    onHitJavaClassInitializationBreakpoint = pyqtSignal(str, name='onHitJavaClassInitializationBreakpoint')
    # watchpoint related
    onWatchpointAdded = pyqtSignal(Watchpoint, name='onWatchpointAdded')
    onWatchpointRemoved = pyqtSignal(str, name='onWatchpointRemoved')
    # ranges + modules
    onSetRanges = pyqtSignal(list, name='onSetRanges')
    onSearchableRanges = pyqtSignal(list, name='onSearchableRanges')
    onSetModules = pyqtSignal(list, name='onSetModules')
    onLogToConsole = pyqtSignal(str, name='onLogToConsole')
    onLogEvent = pyqtSignal(str, name='onLogEvent')
    # thread+context
    onThreadResumed = pyqtSignal(int, name='onThreadResumed')
    onRequestJsThreadResume = pyqtSignal(int, name='onRequestJsThreadResume')
    onApplyContext = pyqtSignal(dict, name='onApplyContext')
    # java
    onEnumerateJavaClassesStart = pyqtSignal(name='onEnumerateJavaClassesStart')
    onEnumerateJavaClassesMatch = pyqtSignal(str, name='onEnumerateJavaClassesMatch')
    onEnumerateJavaClassesComplete = pyqtSignal(name='onEnumerateJavaClassesComplete')
    onEnumerateJavaMethodsComplete = pyqtSignal(list, name='onEnumerateJavaMethodsComplete')
    # objc
    onEnumerateObjCModules = pyqtSignal(list, name='onEnumerateObjCModules')
    onEnumerateObjCClassesStart = pyqtSignal(name='onEnumerateObjCClassesStart')
    onEnumerateObjCMethodsStart = pyqtSignal(name='onEnumerateObjCMethodsStart')
    onEnumerateObjCClassesMatch = pyqtSignal(str, name='onEnumerateObjCClassesMatch')
    onEnumerateObjCMethodsMatch = pyqtSignal(str, name='onEnumerateObjCMethodsMatch')
    onEnumerateObjCClassesComplete = pyqtSignal(name='onEnumerateObjCClassesComplete')
    onEnumerateObjCMethodsComplete = pyqtSignal(name='onEnumerateObjCMethodsComplete')
    # trace
    onJavaTraceEvent = pyqtSignal(list, name='onJavaTraceEvent')
    onSetData = pyqtSignal(list, name='onSetData')

    onBackTrace = pyqtSignal(dict, name='onBackTrace')

    onMemoryScanResult = pyqtSignal(list, name='onMemoryScanResult')

    onContextChanged = pyqtSignal(str, str, name='onContextChanged')

    onReceiveCmd = pyqtSignal(list, name="onReceiveCmd")

    onModuleLoaded = pyqtSignal(list, name='onModuleLoaded')

    # ************************************************************************
    # **************************** Init **************************************
    # ************************************************************************
    def __init__(self, session=None, parent=None, device=None):
        super(Dwarf, self).__init__(parent=parent)
        self._app_window = parent

        self.database = Database()
        self.io = IO(self)

        self.keystone_installed = False
        try:
            import keystone.keystone_const
            self.keystone_installed = True
        except:
            pass

        self.java_available = False

        # frida device
        self._device = device

        # process
        self._pid = 0
        self._package = None
        self._process = None
        self._script = None
        self._spawned = False
        self._resumed = False

        # kernel
        self._kernel = Kernel(self)

        # breakpoints
        self.breakpoints = {}
        self.java_breakpoints = {}
        self.objc_breakpoints = {}
        self.module_initialization_breakpoints = {}
        self.java_class_initialization_breakpoints = {}
        self.watchpoints = {}

        # context
        self._arch = ''
        self._pointer_size = 0
        self.contexts = {}
        self.context_tid = 0
        self._platform = ''

        # connect to self
        self.onApplyContext.connect(self._on_apply_context)
        self.onRequestJsThreadResume.connect(self._on_request_resume_from_js)

        # disassembler
        self.disassembler = Disassembler(self)

    def reinitialize(self):
        self.database = Database()
        self.io = IO(self)

        self._pid = 0
        self._package = None
        self._process = None
        self._script = None
        self._spawned = False
        self._resumed = False

        self.java_available = False

        # frida device
        self._device = None

        # process
        self._process = None
        self._script = None

        # breakpoints
        self.breakpoints = {}
        self.java_breakpoints = {}
        self.module_initialization_breakpoints = {}
        self.java_class_initialization_breakpoints = {}

        self.context_tid = 0

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def kernel(self):
        return self._kernel

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

    @property
    def script(self):
        return self._script

    @property
    def package(self):
        return self._package

    @device.setter
    def device(self, value):
        try:
            if isinstance(value, frida.core.Device):
                self._device = value
        except ValueError:
            self._device = None

    @property
    def resumed(self):
        return self._resumed is True

    def current_context(self):
        key = str(self.context_tid)
        if key in self.contexts:
            return self.contexts[key]
        return None

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def is_address_watched(self, ptr):
        ptr = utils.parse_ptr(ptr)
        if hex(ptr) in self.watchpoints:
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
                raise Exception('Frida Error: ' + str(error))

        if isinstance(pid, list):
            if len(pid) > 1:
                name = pid[1]
            else:
                name = ''
            pid = pid[0]
        else:
            name = ''

        if not isinstance(pid, int):
            raise Exception('Error pid!=int')

        try:
            self._process = self.device.attach(pid)
            self._process.on('detached', self._on_detached)
            self._pid = pid
        except frida.ProcessNotFoundError:
            error_msg = 'Process not found (ProcessNotFoundError)'
            was_error = True
        except frida.ProcessNotRespondingError:
            error_msg = 'Process not responding (ProcessNotRespondingError)'
            was_error = True
        except frida.TimedOutError:
            error_msg = 'Frida timeout (TimedOutError)'
            was_error = True
        except frida.ServerNotRunningError:
            error_msg = 'Frida not running (ServerNotRunningError)'
            was_error = True
        except frida.TransportError:
            error_msg = 'Frida timeout was reached (TransportError)'
            was_error = True
        # keep for debug
        except Exception as error:  # pylint: disable=broad-except
            error_msg = error
            was_error = True

        if was_error:
            raise Exception(error_msg)

        self.onProcessAttached.emit([self.pid, name])
        self.load_script(script=script)

    def detach(self):
        if self._script is not None:
            self.dwarf_api('_detach')
            self._script.unload()
        if self._process is not None:
            self._process.detach()
            if self._spawned:
                try:
                    self.device.kill(self.pid)
                except frida.ProcessNotFoundError:
                    pass

    def load_script(self, script=None, spawned=False, break_at_start=False):
        try:
            if not os.path.exists(utils.resource_path('lib/core.js')):
                raise self.CoreScriptNotFoundError('core.js not found!')

            with open(utils.resource_path('lib/core.js'), 'r') as core_script:
                script_content = core_script.read()

            self._script = self._process.create_script(script_content, runtime='v8')
            self._script.on('message', self._on_message)
            self._script.on('destroyed', self._on_script_destroyed)
            self._script.load()

            break_at_start = break_at_start or self._app_window.dwarf_args.break_start
            # we invalidate the arg in any case (set this from ui needs a store in args for an eventual restore session)
            self._app_window.dwarf_args.break_start = break_at_start

            is_debug = self._app_window.dwarf_args.debug_script
            # this break_at_start have same behavior from args or from the checkbox i added
            self._script.exports.init(break_at_start, is_debug, spawned, True)

            if not os.path.exists(utils.home_path() + 'keywords.json'):
                self.dump_keywords()

            # resume immediately
            self.resume_proc()

            for plugin in self._app_window.plugin_manager.plugins:
                plugin_instance = self._app_window.plugin_manager.plugins[plugin]
                try:
                    self.dwarf_api('evaluateFunction', plugin_instance.__get_agent__())
                except Exception as e:
                    pass

            if script is not None:
                if os.path.exists(script):
                    with open(script, 'r') as script_file:
                        user_script = script_file.read()

                    self.dwarf_api('evaluateFunction', user_script)

            self.onScriptLoaded.emit()

            return 0
        except frida.ProcessNotFoundError:
            error_msg = 'Process not found (ProcessNotFoundError)'
            was_error = True
        except frida.ProcessNotRespondingError:
            error_msg = 'Process not responding (ProcessNotRespondingError)'
            was_error = True
        except frida.TimedOutError:
            error_msg = 'Frida timeout (TimedOutError)'
            was_error = True
        except frida.ServerNotRunningError:
            error_msg = 'Frida not running (ServerNotRunningError)'
            was_error = True
        except frida.TransportError:
            error_msg = 'Frida timeout was reached (TransportError)'
            was_error = True

        if was_error:
            utils.show_message_box(error_msg)
        return 1

    def dump_keywords(self):
        kw = sorted(self._script.exports.keywords())
        with open(utils.home_path() + 'keywords.json', 'w') as f:
            f.write(json.dumps(kw))

    def spawn(self, package, args=None, script=None, break_at_start=False):
        if self.device is None:
            raise self.NoDeviceAssignedError('No Device assigned')

        if args is None:
            args = []

        if self._process is not None:
            self.detach()
        try:
            if package == '-':
                self.attach([os.getpid()], script=script)
            else:
                if self.device.type == 'local':
                    self._pid = self.device.spawn([package] + args)
                else:
                    # args not supported in remote targets
                    self._pid = self.device.spawn(package)
                self._package = package
                self._process = self.device.attach(self._pid)
                self._process.on('detached', self._on_detached)
                self._spawned = True
        except Exception as e:
            raise Exception('Frida Error: ' + str(e))

        self.onProcessAttached.emit([self.pid, package])
        self.load_script(script=script, spawned=True, break_at_start=break_at_start)
        return self.pid

    def resume_proc(self):
        if self._spawned and not self._resumed:
            self._resumed = True
            try:
                self.device.resume(self._pid)
            except frida.InvalidOperationError:
                # already resumed from other loc
                pass

    def add_watchpoint(self, ptr=None):
        if ptr is None:
            ptr, input = InputDialog.input_pointer(self._app_window)
            if ptr == 0:
                return
        return self.dwarf_api('addWatchpoint', ptr)

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
            if data is not None and len(data) > 1:
                with open(file_path, 'wb') as f:
                    f.write(data[1])

    def dwarf_api(self, api, args=None, tid=0):
        if self.pid and self._pid == 0 or self.process is None:
            return

        # when tid is 0 we want to execute the api in the current breakpointed thread
        # however, when we release from menu, what we want to do is to release multiple contexts at once
        # so that we pass 0 as tid.
        # we check here and setup special rules for release api
        is_releasing = api == 'release'
        if not is_releasing and tid == 0:
            tid = self.context_tid

        if args is not None and not isinstance(args, list):
            args = [args]
        if self._script is None:
            return None
        try:
            if tid == 0:
                for tid in list(self.contexts.keys()):
                    self._script.post({"type": tid})
                    if is_releasing:
                        self._script.exports.api(int(tid), api, [int(tid)])
                if is_releasing:
                    return None
            else:
                self._script.post({"type": str(tid)})
            return self._script.exports.api(tid, api, args)
        except Exception as e:
            self.log_event(str(e))
            return None

    def breakpoint_java(self, input_=None, pending_args=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(
                self._app_window, hint='insert java class or method',
                placeholder='com.package.class or com.package.class.method')
            if not accept:
                return
        self.java_pending_args = pending_args
        input_ = input_.replace(' ', '')
        self.dwarf_api('putBreakpoint', input_)

    def breakpoint_objc(self, input_=None, pending_args=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(
                self._app_window, hint='insert obj class or method',
                placeholder='com.package.class or com.package.class.method') #todo
            if not accept:
                return
        self.objc_pending_args = pending_args
        self.dwarf_api('putBreakpoint', input_)

    def breakpoint_native(self, input_=None):
        if input_ is None or not isinstance(input_, str):
            ptr, input_ = InputDialog.input_pointer(self._app_window)
        else:
            ptr = utils.parse_ptr(self._app_window.dwarf.dwarf_api('evaluatePtr', input_))
        if ptr > 0:
            self.dwarf_api('putBreakpoint', ptr)

    def breakpoint_module_initialization(self, input_=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(self._app_window, hint='insert module name', placeholder='libtarget.so')
            if not accept:
                return
            if len(input_) == 0:
                return

        if input_ in self.module_initialization_breakpoints:
            return

        self.dwarf_api('putModuleInitializationBreakpoint', input_)

    def breakpoint_java_class_initialization(self, input_=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(
                self._app_window, hint='insert class name', placeholder='com.android.mytargetclass')
            if not accept:
                return
            if len(input_) == 0:
                return

        if input_ in self.java_class_initialization_breakpoints:
            return

        self.dwarf_api('putJavaClassInitializationBreakpoint', input_)

    def log(self, what):
        self.onLogToConsole.emit(str(what))

    def log_event(self, what):
        self.onLogEvent.emit(str(what))

    def read_memory(self, ptr, length):
        return self.io.read(ptr, length)

    def read_memory_async(self, ptr, length, callback):
        """
        def callback(ptr, data):
        """
        self.io.read_async(ptr, length, callback)

    def read_range(self, ptr):
        return self.io.read_range(ptr)

    def read_range_async(self, ptr, callback):
        """
        def callback(base, data, offset):
        """
        self.io.read_range_async(ptr, callback)

    def remove_watchpoint(self, ptr):
        return self.dwarf_api('removeWatchpoint', ptr)

    def search(self, start, size, pattern):
        # sanify args
        start = utils.parse_ptr(start)
        size = int(size)
        # convert to frida accepted pattern
        pattern = ' '.join([pattern[i:i + 2] for i in range(0, len(pattern), 2)])
        self.dwarf_api('memoryScan', [start, size, pattern])

    def search_list(self, ranges_list, pattern):
        pattern = ' '.join([pattern[i:i + 2] for i in range(0, len(pattern), 2)])
        self.dwarf_api('memoryScanList', [json.dumps(ranges_list), pattern])

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_detached(self, process, reason, crash_log):
        self.onProcessDetached.emit([process, reason, crash_log])

    def _on_script_destroyed(self):
        self._script = None

    def _on_message(self, message, data):
        QApplication.processEvents()
        if 'payload' not in message:
            print('payload: ' + str(message))
            return

        self.onReceiveCmd.emit([message, data])

        what = message['payload']
        parts = what.split(':::')
        if len(parts) < 2:
            return

        cmd = parts[0]
        if cmd == 'api_ping_timeout':
            self._script.post({"type": str(parts[1])})
        elif cmd == 'backtrace':
            self.onBackTrace.emit(json.loads(parts[1]))
        elif cmd == 'class_loader_loading_class':
            str_fmt = ('@thread {0} loading class := {1}'.format(parts[1], parts[2]))
            self.log_event(str_fmt)
        elif cmd == 'enumerate_java_classes_start':
            self.onEnumerateJavaClassesStart.emit()
        elif cmd == 'enumerate_java_classes_match':
            self.onEnumerateJavaClassesMatch.emit(parts[1])
        elif cmd == 'enumerate_java_classes_complete':
            self.onEnumerateJavaClassesComplete.emit()
        elif cmd == 'enumerate_java_methods_complete':
            self.onEnumerateJavaMethodsComplete.emit([parts[1], json.loads(parts[2])])
        elif cmd == 'enumerate_objc_modules':
            modules = json.loads(parts[1])
            self.onEnumerateObjCModules.emit(modules)
        elif cmd == 'enumerate_objc_classes_start':
            self.onEnumerateObjCClassesStart.emit()
        elif cmd == 'enumerate_objc_classes_match':
            self.onEnumerateObjCClassesMatch.emit(parts[1])
        elif cmd == 'enumerate_objc_classes_complete':
            self.onEnumerateObjCClassesComplete.emit()
        elif cmd == 'enumerate_objc_methods_start':
            self.onEnumerateObjCMethodsStart.emit()
        elif cmd == 'enumerate_objc_methods_match':
            self.onEnumerateObjCMethodsMatch.emit(parts[1])
        elif cmd == 'enumerate_objc_methods_complete':
            self.onEnumerateObjCMethodsComplete.emit()
        elif cmd == 'ftrace':
            if self.app.get_ftrace_panel() is not None:
                self.app.get_ftrace_panel().append_data(parts[1])
        elif cmd == 'enable_kernel':
            self._app_window.get_menu().enable_kernel_menu()
        elif cmd == 'breakpoint_java_callback':
            b = Breakpoint(BREAKPOINT_JAVA)
            b.set_target(parts[1])
            if len(parts) > 2:
                b.set_condition(parts[2])
            self.java_breakpoints[parts[1]] = b
            self.onAddJavaBreakpoint.emit(b)
        elif cmd == 'breakpoint_objc_callback':
            b = Breakpoint(BREAKPOINT_OBJC)
            # WORKAROUND: Some ObjC Methods have multiple ':' in name. Restoring ':::':
            target = ":::".join(parts[1:-1])
            b.set_target(target)
            if parts[-1] != '':
                b.set_condition(parts[-1])
            self.objc_breakpoints[target] = b
            self.onAddObjCBreakpoint.emit(b)
        elif cmd == 'java_class_initialization_callback':
            b = Breakpoint(BREAKPOINT_INITIALIZATION)
            b.set_target(parts[1])
            b.set_debug_symbol(parts[1])
            self.java_class_initialization_breakpoints[parts[1]] = b
            self.onAddJavaClassInitializationBreakpoint.emit(b)
        elif cmd == 'breakpoint_native_callback':
            b = Breakpoint(BREAKPOINT_NATIVE)
            b.set_target(int(parts[1], 16))
            if len(parts) > 2:
                b.set_condition(parts[2])
            self.breakpoints[b.get_target()] = b
            self.onAddNativeBreakpoint.emit(b)
        elif cmd == 'module_initialization_callback':
            b = Breakpoint(BREAKPOINT_INITIALIZATION)
            b.set_target(parts[1])
            self.module_initialization_breakpoints[parts[1]] = b
            self.onAddModuleInitializationBreakpoint.emit(b)
        elif cmd == 'breakpoint_deleted':
            if parts[1] == 'java':
                self.java_breakpoints.pop(parts[2])
            elif parts[1] == 'objc':
                self.objc_breakpoints.pop(":::".join(parts[2:]))
            elif parts[1] == 'module_initialization':
                if parts[2] in self.module_initialization_breakpoints:
                    self.module_initialization_breakpoints.pop(parts[2])
            elif parts[1] == 'java_class_initialization':
                if parts[2] in self.java_class_initialization_breakpoints:
                    self.java_class_initialization_breakpoints.pop(parts[2])
            else:
                self.breakpoints.pop(utils.parse_ptr(parts[2]))
            self.onDeleteBreakpoint.emit(parts)
        elif cmd == 'breakpoint_java_class_initialization_callback':
            str_fmt = ('Breakpoint java class initialization {0} @thread := {1}'.format(parts[1], parts[2]))
            self.log_event(str_fmt)
            self.onHitJavaClassInitializationBreakpoint.emit(parts[1])
        elif cmd == 'java_trace':
            self.onJavaTraceEvent.emit(parts)
        elif cmd == 'log':
            self.log(parts[1])
        elif cmd == 'breakpoint_module_initialization_callback':
            data = json.loads(parts[2])
            str_fmt = ('Breakpoint module initialization {0} @thread := {1}'.format(data['module'], parts[1]))
            self.log_event(str_fmt)
            self.onHitModuleInitializationBreakpoint.emit([parts[1], data])
        elif cmd == 'module_initialized':
            module = json.loads(parts[2])
            if module is not None:
                str_fmt = ('@thread {0} loading module := {1}'.format(parts[1], module['name']))
                self.log_event(str_fmt)

                module_info = ModuleInfo.build_module_info_with_data(module)
                self.database.put_module_info(module_info.base, module_info)

                self.onModuleLoaded.emit([module])
        elif cmd == 'new_thread':
            str_fmt = ('@thread {0} starting new thread with target fn := {1}'.format(parts[1], parts[2]))
            self.log_event(str_fmt)
        elif cmd == 'release':
            reason = 0
            if len(parts) > 1:
                reason = int(parts[2])
            p = 'releasing' if reason != 3 else 'stepping'
            str_fmt = (p + ' := {0}'.format(parts[1]))
            self.log_event(str_fmt)
            if parts[1] in self.contexts:
                del self.contexts[parts[1]]
            self.onThreadResumed.emit(int(parts[1]))
        elif cmd == 'resume':
            if not self.resumed:
                self.resume_proc()
        elif cmd == 'release_js':
            # releasing the thread must be done by calling py funct dwarf_api('release')
            # there are cases in which we want to release the thread from a js api so we need to call this
            self.onRequestJsThreadResume.emit(int(parts[1]))
        elif cmd == 'set_context':
            #data = json.loads(parts[1])
            # WORKAROUND: Some ObjC Methods have multiple ':' in name. Restoring ':::'
            data = json.loads(":::".join(parts[1:]))
            if 'modules' in data:
                self.onSetModules.emit(data['modules'])
            if 'ranges' in data:
                self.onSetRanges.emit(data['ranges'])
            if 'backtrace' in data:
                self.onBackTrace.emit(data['backtrace'])

            self.onApplyContext.emit(data)
        elif cmd == 'set_context_value':
            context_property = parts[1]
            value = parts[2]
            self.onContextChanged.emit(str(context_property), value)
        elif cmd == 'set_data':
            if data is not None:
                self.onSetData.emit(['raw', parts[1], data])
            else:
                self.onSetData.emit(['plain', parts[1], str(parts[2])])
        elif cmd == 'unhandled_exception':
            # todo
            pass
        elif cmd == 'update_modules':
            modules = json.loads(parts[2])
            self.onSetModules.emit(modules)
        elif cmd == 'update_ranges':
            self.onSetRanges.emit(json.loads(parts[2]))
        elif cmd == 'update_searchable_ranges':
            self.onSearchableRanges.emit(json.loads(parts[2]))
        elif cmd == 'watchpoint':
            exception = json.loads(parts[1])
            self.log_event('watchpoint hit op %s address %s @thread := %s' %
                           (exception['memory']['operation'], exception['memory']['address'], parts[2]))
        elif cmd == 'watchpoint_added':
            ptr = utils.parse_ptr(parts[1])
            hex_ptr = hex(ptr)
            flags = int(parts[2])

            w = Watchpoint(ptr, flags)
            w.set_debug_symbol(json.loads(parts[3]))
            self.watchpoints[hex_ptr] = w

            self.onWatchpointAdded.emit(w)
        elif cmd == 'watchpoint_removed':
            hex_ptr = hex(utils.parse_ptr(parts[1]))
            self.watchpoints.pop(hex_ptr)
            self.onWatchpointRemoved.emit(hex_ptr)
        elif cmd == 'memoryscan_result':
            if parts[1] == '':
                self.onMemoryScanResult.emit([])
            else:
                self.onMemoryScanResult.emit(json.loads(parts[1]))

    def _on_apply_context(self, context_data):
        reason = context_data['reason']
        if reason == -1:
            # set initial context
            self._arch = context_data['arch']
            self._platform = context_data['platform']
            self._pointer_size = context_data['pointerSize']
            self.java_available = context_data['java']
            str_fmt = ('injected into := {0:d}'.format(self.pid))
            self.log_event(str_fmt)
        elif 'context' in context_data:
            context = Context(context_data['context'])
            self.contexts[str(context_data['tid'])] = context

            sym = ''
            if 'pc' in context_data['context']:
                name = context_data['ptr']
                if 'symbol' in context_data['context']['pc'] and \
                        context_data['context']['pc']['symbol']['name'] is not None:
                    sym = context_data['context']['pc']['symbol']['moduleName']
                    sym += ' - '
                    sym += context_data['context']['pc']['symbol']['name']
            else:
                name = context_data['ptr']

            if context_data['reason'] == 0:
                self.log_event('breakpoint %s %s @thread := %d' % (name, sym, context_data['tid']))

        if not reason == -1 and self.context_tid == 0:
            self.context_tid = context_data['tid']

    def _on_request_resume_from_js(self, tid):
        self.dwarf_api('release', tid, tid=tid)

    def restart_proc(self):
        session = self.dump_session()

        self.reinitialize()
        self._app_window.session_manager._session = None
        self._app_window.session_stopped()

        self._app_window._restore_session(session)

    def dump_session(self):
        return {
            'session': self._app_window.session_manager.session.session_type,
            'package': self._package,
            'user_script': self._app_window.console_panel.get_js_console().function_content
        }
