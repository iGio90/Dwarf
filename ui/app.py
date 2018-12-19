import json
import threading

from ui.layout import Layout
from ui.panel_contexts import ContextsPanel
from ui.panel_main import MainPanel
from ui.panel_hooks import HooksPanel

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from ui.panel_modules import ModulesPanel
from ui.panel_ranges import RangesPanel
from ui.panel_vars import VarsPanel


class App(QWidget):
    def __init__(self, qtapp, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.qtapp = qtapp

        self.script = None
        self.arch = ''
        self.pointer_size = 0

        self.modules_panel = None
        self.ranges_panel = None
        self.main_panel = None
        self.hooks_panel = None
        self.contexts_panel = None
        self.vars_panel = None

        self.loading_library = False

        self.contexts = []

        box = QVBoxLayout()

        main_splitter = Layout(self)
        main_splitter.addWidget(self.build_left_column())
        main_splitter.addWidget(self.build_central_content())
        main_splitter.setStretchFactor(0, 2)
        main_splitter.setStretchFactor(1, 5)

        box.addWidget(main_splitter)
        self.setLayout(box)

    def build_left_column(self):
        splitter = QSplitter()
        splitter.setOrientation(Qt.Vertical)

        self.hooks_panel = HooksPanel(self)
        splitter.addWidget(self.hooks_panel)

        self.contexts_panel = ContextsPanel(self, 0, 3)
        splitter.addWidget(self.contexts_panel)

        self.vars_panel = VarsPanel(self)
        splitter.addWidget(self.vars_panel)

        return splitter

    def build_central_content(self):
        q = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter()

        self.main_panel = MainPanel(self)
        splitter.addWidget(self.main_panel)

        right_splitter = QSplitter()
        right_splitter.setOrientation(Qt.Vertical)

        self.modules_panel = ModulesPanel(self, 0, 3)
        right_splitter.addWidget(self.modules_panel)

        self.ranges_panel = RangesPanel(self, 0, 4)
        right_splitter.addWidget(self.ranges_panel)

        splitter.addWidget(right_splitter)

        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

        bq = QWidget()
        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)

        bt = QPushButton('release')
        bt.clicked.connect(self.release_target)
        buttons.addWidget(bt)

        bt = QPushButton('restart')
        bt.clicked.connect(self.restart_target)
        buttons.addWidget(bt)

        buttons.addWidget(QPushButton('tools'))
        buttons.addWidget(QPushButton('options'))

        bq.setLayout(buttons)
        bq.setMaximumHeight(50)
        bq.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(bq)

        q.setLayout(layout)
        q.setContentsMargins(0, 0, 0, 0)

        return q

    def set_modules(self, modules):
        self.modules_panel.set_modules(modules)

    def set_ranges(self, ranges):
        self.ranges_panel.set_ranges(ranges)

    def initialize_with_script(self, script):
        self.script = script
        self.script.on('message', self.on_message)
        self.script.on('destroyed', self.on_destroyed)
        self.showMaximized()

    def on_message(self, message, data):
        if 'payload' not in message:
            print(message)
            return

        what = message['payload']
        parts = what.split(':::')
        if len(parts) < 2:
            print(what)
            return

        if parts[0] == '0':
            self.main_panel.add_to_main_content_content(parts[1], scroll=True)
        elif parts[0] == '1':
            data = json.loads(parts[1])
            self.contexts.append(data)

            if len(data['context']) > 0:
                self.hooks_panel.increment_hook_count(int(data['context']['pc'], 16))
                if 'moduleName' in data['symbol']:
                    sym = '%s - %s' % (data['symbol']['moduleName'], data['symbol']['name'])
                else:
                    sym = self.hooks_panel.get_hooks()[int(data['context']['pc'], 16)]['input']
                self.contexts_panel.add_context(data, library_onload=self.loading_library)
                if self.loading_library is None:
                    self.main_panel.add_to_main_content_content('hook %s (%s) @thread := %d' % (
                        data['context']['pc'], sym, data['tid']), scroll=True)
                if len(self.contexts) > 1:
                    return
            else:
                self.arch = data['arch']
                if self.get_arch() == 'arm':
                    self.pointer_size = 4
                else:
                    self.pointer_size = 8
                self.main_panel.add_to_main_content_content('injected into := ' + str(data['pid']))

            self.apply_context(data)
            if self.loading_library is not None:
               self.loading_library = None
        elif parts[0] == '2':
            print(parts)
            self.loading_library = parts[1]
            self.main_panel.add_to_main_content_content('hook onload %s @thread := %s' % (
                parts[1], parts[3]), scroll=True)
            self.hooks_panel.hit_onload(parts[1], parts[2])
        else:
            print(what)

    def get_arch(self):
        return self.arch

    def get_script(self):
        return self.script

    def get_memory_panel(self):
        return self.main_panel.get_memory_panel()

    def get_pointer_size(self):
        return self.pointer_size

    def release_target(self, tid=0):
        if tid > 0:
            self.get_script().exports.release(tid)
        else:
            self.contexts_panel.setRowCount(0)
            self.contexts.clear()
            self.main_panel.release_target()

            self.get_script().exports.release()

    def restart_target(self):
        self.script.exports.restart()
        self.release_target()
        self.hooks_panel.reset_hook_count()
        self.contexts_panel.setRowCount(0)

    def _apply_context(self, context):
        if 'modules' in context:
            self.set_modules(context['modules'])
        if 'ranges' in context:
            self.set_ranges(context['ranges'])
        if 'context' in context:
            self.main_panel.set_context(context['context'])

    def apply_context(self, context):
        threading.Thread(target=self._apply_context, args=(context,)).start()

    def on_destroyed(self):
        print('[*] script destroyed')
        self.qtapp.exit()
