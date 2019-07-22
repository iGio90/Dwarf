from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QMainWindow, QDockWidget, QWidget

from lib import utils
from lib.types.range import Range
from ui.dialogs.dialog_input import InputDialog
from ui.widgets.disasm_view import DisassemblyView
from ui.widgets.hex_edit import HexEditor
from ui.widgets.list_view import DwarfListView


DEBUG_VIEW_MEMORY = 0
DEBUG_VIEW_DISASSEMBLY = 1


class QDebugCentralView(QMainWindow):
    def __init__(self, app, flags=None):
        super(QDebugCentralView, self).__init__(flags)
        self.setDockOptions(QMainWindow.AnimatedDocks | QMainWindow.AllowNestedDocks | QMainWindow.AllowTabbedDocks)

        self.app = app
        self.dwarf = app.dwarf

        self.current_memory_address = 0
        self.current_disassembly_address = 0

        m_width = self.app.screen_geometry.width()

        self.memory_panel = HexEditor(self.app)
        self.memory_panel.debug_panel = self
        self.memory_panel.dataChanged.connect(self.on_memory_modified)

        self.disassembly_panel = DisassemblyView(self.app)
        self.disassembly_panel.debug_panel = self

        self.dock_memory_panel = QDockWidget('Memory', self)
        self.dock_memory_panel.setWidget(self.memory_panel)

        self.dock_disassembly_panel = QDockWidget('Disassembly', self)
        self.dock_disassembly_panel.setWidget(self.disassembly_panel)

        if m_width >= 1920:
            self.addDockWidget(Qt.LeftDockWidgetArea, self.dock_memory_panel)
            self.addDockWidget(Qt.RightDockWidgetArea, self.dock_disassembly_panel)
        else:
            self.addDockWidget(Qt.LeftDockWidgetArea, self.dock_memory_panel)
            self.addDockWidget(Qt.LeftDockWidgetArea, self.dock_disassembly_panel)
            self.tabifyDockWidget(self.dock_memory_panel, self.dock_disassembly_panel)

    def on_memory_modified(self, pos, length):
        data_pos = self.memory_panel.base + pos
        data = self.memory_panel.data[pos:pos + length]
        data = [data[0]]  # todo: strange js part

        if self.dwarf.dwarf_api('writeBytes', [data_pos, data]):
            pass
        else:
            utils.show_message_box('Failed to write Memory')

    def raise_memory_panel(self):
        self.dock_memory_panel.raise_()

    def raise_disassembly_panel(self):
        self.dock_disassembly_panel.raise_()

    def jump_to_address(self, address, view=DEBUG_VIEW_MEMORY):
        address = utils.parse_ptr(address)

        if view == DEBUG_VIEW_MEMORY:
            if self.current_memory_address > 0:
                if self.is_address_in_view(view, address):
                    return

        elif view == DEBUG_VIEW_DISASSEMBLY:
            self.current_disassembly_address = address

            if self.current_disassembly_address > 0:
                if self.is_address_in_view(view, address):
                    return

        Range.build_or_get(self.app.dwarf, address, cb=lambda x: self.apply_range(address, x, view=view))

    def apply_range(self, address, dwarf_range, view=DEBUG_VIEW_MEMORY):
        if view == DEBUG_VIEW_MEMORY:
            self.current_memory_address = address
            self.memory_panel.set_data(dwarf_range.data, base=dwarf_range.base, focus_address=address)
            self.raise_memory_panel()

            if self.current_disassembly_address == 0:
                self.current_disassembly_address = address
                self.disassembly_panel.apply_range(dwarf_range)
        elif view == DEBUG_VIEW_DISASSEMBLY:
            self.current_disassembly_address = address
            self.disassembly_panel.apply_range(dwarf_range)
            self.raise_disassembly_panel()

            if self.current_memory_address == 0:
                self.current_memory_address = address
                self.memory_panel.set_data(dwarf_range.data, base=dwarf_range.base, focus_address=address)

    def is_address_in_view(self, view, address):
        if view == DEBUG_VIEW_MEMORY:
            ptr_exists = self.memory_panel.base <= address <= self.memory_panel.base + len(self.memory_panel.data)
            if ptr_exists:
                self.current_memory_address = address
                self.memory_panel.caret.position = address - self.memory_panel.base
                return True
        elif view == DEBUG_VIEW_DISASSEMBLY:
            line_index_for_address = self.disassembly_panel.get_line_for_address(address)
            if line_index_for_address >= 0:
                self.current_disassembly_address = address
                self.disassembly_panel.verticalScrollBar().setValue(line_index_for_address)
                return True
        return False

    def on_cm_jump_to_address(self, view=DEBUG_VIEW_MEMORY):
        ptr, _ = InputDialog.input_pointer(self.app)
        if ptr > 0:
            self.jump_to_address(ptr, view=view)

    def dump_data(self, address, _len):
        def _dump(dwarf_range):
            if address + _len > dwarf_range.tail:
                self.display_error('length is higher than range size')
            else:
                data = dwarf_range.data[address:address + _len]
                if data is not None:
                    from PyQt5.QtWidgets import QFileDialog
                    _file = QFileDialog.getSaveFileName(self.app)
                    with open(_file[0], 'wb') as f:
                        f.write(data)
        Range.build_or_get(self.app.dwarf, address, cb=_dump)


class QDebugPanel(QMainWindow):
    def __init__(self, app, flags=None):
        super(QDebugPanel, self).__init__(flags)
        self.setDockOptions(QMainWindow.AnimatedDocks | QMainWindow.AllowNestedDocks)

        self.app = app

        self.functions_list = DwarfListView()
        self.functions_list_model = QStandardItemModel(0, 1)
        self.functions_list_model.setHeaderData(0, Qt.Horizontal, '')
        self.functions_list.setModel(self.functions_list_model)
        self.functions_list.setHeaderHidden(True)
        self.functions_list.doubleClicked.connect(self._function_double_clicked)

        self.dock_functions_list = QDockWidget('Functions', self)
        self.dock_functions_list.setWidget(self.functions_list)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.dock_functions_list)
        self.dock_functions_list.hide()

        self.debug_central_view = QDebugCentralView(self.app)
        self.setCentralWidget(self.debug_central_view)

        self.update_functions()

    @property
    def current_disassembly_address(self):
        return self.debug_central_view.current_disassembly_address

    @property
    def current_memory_address(self):
        return self.debug_central_view.current_memory_address

    @property
    def memory_panel(self):
        return self.debug_central_view.memory_panel

    def update_functions(self, functions_list=None):
        if functions_list is None:
            functions_list = {}
        self.functions_list_model.setRowCount(0)
        for module_info_base in self.app.dwarf.database.modules_info:
            module_info = self.app.dwarf.database.modules_info[module_info_base]
            if len(module_info.functions) > 0:
                self.functions_list.show()
                for function in module_info.functions:
                    functions_list[function.name] = function.address

        for function_name in sorted(functions_list.keys()):
            function_addr = functions_list[function_name]
            item = QStandardItem(function_name.replace('.', '_'))
            item.setData(function_addr, Qt.UserRole + 2)
            self.functions_list_model.appendRow([item])

        if self.functions_list_model.rowCount() > 0:
            self.dock_functions_list.show()
        else:
            self.dock_functions_list.hide()

    def _function_double_clicked(self, model_index):
        item = self.functions_list_model.itemFromIndex(model_index)
        address = item.data(Qt.UserRole + 2)
        self.jump_to_address(address, view=DEBUG_VIEW_DISASSEMBLY)

    def jump_to_address(self, address, view=DEBUG_VIEW_MEMORY):
        self.debug_central_view.jump_to_address(address, view=view)

    def on_context_setup(self):
        self.debug_central_view.memory_panel.on_context_setup()

    def raise_memory_panel(self):
        self.debug_central_view.dock_memory_panel.raise_()

    def raise_disassembly_panel(self):
        self.debug_central_view.dock_disassembly_panel.raise_()
