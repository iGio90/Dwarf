"""
Dwarf - Copyright (C) 2019 iGio90

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
import json

import frida
from hexdump import hexdump

from lib import utils
from lib.hook import Hook
from lib.prefs import Prefs
from ui.panel_search import SearchPanel


class Dwarf(object):
    def __init__(self, app_window):
        self.app_window = app_window
        self.app = app_window.get_app_instance()

        self.java_available = False
        self.loading_library = False
        self.bytes_search_panel = None

        # process
        self.pid = 0
        self.process = None
        self.script = None

        # hooks
        self.hooks = {}
        self.onloads = {}
        self.java_hooks = {}
        self.temporary_input = ''
        self.native_pending_args = None
        self.java_pending_args = None

        self.prefs = Prefs()

    def attach(self, pid_or_package, script=None):
        if self.process is not None:
            self.detach()

        device = frida.get_usb_device()
        try:
            self.process = device.attach(pid_or_package)
        except Exception as e:
            utils.show_message_box('Failed to attach to %s' % str(pid_or_package), str(e))
            return
        self.load_script(script)

    def detach(self):
        self.dwarf_api('_detach')
        if self.script is not None:
            self.script.unload()
        if self.process is not None:
            self.process.detach()

    def load_script(self, script=None):
        with open('lib/script.js', 'r') as f:
            s = f.read()
        self.script = self.process.create_script(s)
        self.script.on('message', self.on_message)
        self.script.on('destroyed', self.on_destroyed)
        self.script.load()

        if script is not None:
            self.dwarf_api('evaluateFunction', script)

        self.app_window.on_script_loaded()

    def spawn(self, package, script=None):
        if self.process is not None:
            self.detach()

        device = frida.get_usb_device()
        self.app_window.get_adb().kill_package(package)
        try:
            pid = device.spawn(package)
            self.process = device.attach(pid)
        except Exception as e:
            utils.show_message_box('Failed to spawn to %s' % package, str(e))
            return
        self.load_script(script)
        device.resume(pid)

    def on_message(self, message, data):
        if 'payload' not in message:
            print(message)
            return

        what = message['payload']
        parts = what.split(':::')
        if len(parts) < 2:
            print(what)
            return

        if parts[0] == 'log':
            self.app.get_log_panel().log(parts[1])
        elif parts[0] == 'set_context':
            data = json.loads(parts[1])
            self.app.get_contexts().append(data)

            if 'context' in data:
                sym = ''
                if 'pc' in data['context']:
                    name = data['ptr']
                    if 'moduleName' in data['symbol']:
                        sym = '(%s - %s)' % (data['symbol']['moduleName'], data['symbol']['name'])
                else:
                    name = data['ptr']
                self.app.get_contexts_panel().add_context(data, library_onload=self.loading_library)
                if self.loading_library is None:
                    self.app.get_log_panel().log('hook %s %s @thread := %d' % (
                        name, sym, data['tid']))
                self.app.get_session_ui().request_session_ui_focus()
                if len(self.app.get_contexts()) > 1 and self.app.get_registers_panel().have_context():
                    return
            else:
                self.app.set_arch(data['arch'])
                if self.app.get_arch() == 'arm':
                    self.app.pointer_size = 4
                else:
                    self.app.pointer_size = 8
                self.pid = data['pid']
                self.java_available = data['java']
                self.app.get_log_panel().log('injected into := ' + str(self.pid))
                self.app_window.on_context_info()

            self.app.apply_context(data)
            if self.loading_library is not None:
                self.loading_library = None
        elif parts[0] == 'onload_callback':
            self.loading_library = parts[1]
            self.app.get_log_panel().log('hook onload %s @thread := %s' % (
                parts[1], parts[3]))
            self.app.get_hooks_panel().hit_onload(parts[1], parts[2])
        elif parts[0] == 'hook_java_callback':
            h = Hook(Hook.HOOK_JAVA)
            h.set_ptr(1)
            h.set_input(parts[1])
            if self.java_pending_args:
                h.set_condition(self.java_pending_args['condition'])
                h.set_logic(self.java_pending_args['logic'])
                self.java_pending_args = None
            self.java_hooks[h.get_input()] = h
            self.app.get_hooks_panel().hook_java_callback(h)
        elif parts[0] == 'hook_native_callback':
            h = Hook(Hook.HOOK_NATIVE)
            h.set_ptr(int(parts[1], 16))
            h.set_input(self.temporary_input)
            self.temporary_input = ''
            if self.native_pending_args:
                h.set_condition(self.native_pending_args['condition'])
                h.set_logic(self.native_pending_args['logic'])
                self.native_pending_args = None
            self.hooks[h.get_ptr()] = h
            self.app.get_hooks_panel().hook_native_callback(h)
        elif parts[0] == 'memory_scan_finished':
            self.app_window.get_menu().on_bytes_search_finished()
            self.bytes_search_panel = None
        elif parts[0] == 'memory_scan_match':
            self.bytes_search_panel.setColumnCount(2)
            self.bytes_search_panel.setHorizontalHeaderLabels(['address', 'symbol'])
            self.bytes_search_panel.add_bytes_match_item(parts[1], json.loads(parts[2]))
        elif parts[0] == 'set_data':
            key = parts[1]
            if data:
                self.app.get_data_panel().append_data(key, hexdump(data, result='return'))
            else:
                self.app.get_data_panel().append_data(key, str(parts[2]))
        elif parts[0] == 'update_modules':
            self.app.apply_context({'tid': parts[1], 'modules': json.loads(parts[2])})
        else:
            print(what)

    def on_destroyed(self):
        self.app.get_log_panel().log('detached from %d. script destroyed' % self.pid)
        self.app_window.on_script_destroyed()

        self.pid = 0
        self.process = None
        self.script = None

    def dwarf_api(self, api, args=None, tid=0):
        if tid == 0:
            tid = self.app.get_context_tid()
        if args is not None and not isinstance(args, list):
            args = [args]
        if self.script is None:
            return None
        try:
            return self.script.exports.api(tid, api, args)
        except Exception as e:
            self.app.get_log_panel().log(str(e))
            return None

    def hook_java(self, input, pending_args):
        self.java_pending_args = pending_args
        self.app.dwarf_api('hookJava', input)

    def hook_native(self, input, pending_args, ptr):
        self.temporary_input = input
        self.native_pending_args = pending_args
        self.app.dwarf_api('hookNative', ptr)

    def hook_onload(self, input):
        self.dwarf_api('hookOnLoad', input)
        h = Hook(Hook.HOOK_ONLOAD)
        h.set_ptr(0)
        h.set_input(input)

        self.onloads[input] = h
        return h

    def search_bytes(self, input):
        self.bytes_search_panel = SearchPanel.bytes_search_panel(self.app, input)

    def get_loading_library(self):
        return self.loading_library

    def get_prefs(self):
        return self.prefs
