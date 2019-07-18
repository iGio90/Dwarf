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
import json
from math import ceil
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from capstone import *
from capstone.x86_const import *
from capstone.arm64_const import *
from lib.types.range import Range
from lib import utils
from lib.types.instruction import Instruction

from lib.prefs import Prefs
from ui.dialog_input import InputDialog
from ui.widgets.list_view import DwarfListView


class DisassembleThread(QThread):
    onFinished = pyqtSignal(list, name='onFinished')
    onError = pyqtSignal(str, name='onError')

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self._dwarf = None
        self._range = None
        self._capstone = None
        self._num_instructions = 0

    def run(self):
        if self._range is None:
            self.onError.emit('No Range set')
            self.onFinished.emit([])

        _counter = 0
        _instructions = []

        _debug_symbols = []
        _debug_symbols_indexes = []

        for cap_inst in self._capstone.disasm(
                self._range.data[self._range.start_offset:], self._range.start_address):
            if 0 < self._num_instructions < _counter:
                break

            dwarf_instruction = Instruction(self._dwarf, cap_inst)
            if dwarf_instruction.is_jump and dwarf_instruction.jump_address:
                _debug_symbols.append(dwarf_instruction.jump_address)
                _debug_symbols_indexes.append(str(len(_instructions)))
            _instructions.append(dwarf_instruction)

            _counter += 1

            if (cap_inst.group(CS_GRP_RET) or cap_inst.group(ARM64_GRP_RET)) \
                    and self._num_instructions == 0:
                break

        if _debug_symbols:
            symbols = self._dwarf.dwarf_api('getDebugSymbols', json.dumps(_debug_symbols))
            if symbols:
                for i in range(len(symbols)):
                    symbol = symbols[i]
                    instruction = _instructions[int(_debug_symbols_indexes[i])]
                    instruction.symbol_name = symbol['name']
                    instruction.symbol_module = '-'
                    if 'moduleName' in symbol:
                        instruction.symbol_module = symbol['moduleName']

        self.onFinished.emit(_instructions)


class DisassemblyPanel(QSplitter):
    def __init__(self, app):
        super(DisassemblyPanel, self).__init__()

        self.app = app

        self.functions_list = DwarfListView()
        self.functions_list_model = QStandardItemModel(0, 1)
        self.functions_list_model.setHeaderData(0, Qt.Horizontal, 'functions')
        self.functions_list.setModel(self.functions_list_model)
        self.addWidget(self.functions_list)
        self.functions_list.hide()
        self.functions_list.doubleClicked.connect(self._function_double_clicked)

        self.disasm_view = DisassemblyView(app)
        self.addWidget(self.disasm_view)

        self.setStretchFactor(0, 1)
        self.setStretchFactor(1, 5)

    def disassemble(self, dwarf_range):
        self.disasm_view.disassemble(dwarf_range)

    def show_functions_for_module(self, hex_module_base):
        self.functions_list_model.setRowCount(0)
        module_info = self.app.dwarf.database.get_module_info(hex_module_base)
        if module_info is not None:
            if len(module_info.functions) > 0:
                self.functions_list.show()
                for function in sorted(module_info.functions, key=lambda x: x.name):
                    item = QStandardItem(function.name)
                    item.setData(function.address, Qt.UserRole + 2)
                    self.functions_list_model.appendRow([item])
            else:
                self.functions_list.hide()

    def _function_double_clicked(self, model_index):
        item = self.functions_list_model.itemFromIndex(model_index)
        address = item.data(Qt.UserRole + 2)
        self.disasm_view.read_memory(address)


class DisassemblyView(QAbstractScrollArea):
    onDisassemble = pyqtSignal(object, name='onDisassemble')
    onShowMemoryRequest = pyqtSignal(str, int, name='onShowMemoryRequest')

    def __init__(self, parent=None):
        super(DisassemblyView, self).__init__(parent=parent)

        _prefs = Prefs()
        self._uppercase_hex = (_prefs.get('dwarf_ui_hexstyle', 'upper').lower() == 'upper')

        self._app_window = parent

        self.setAutoFillBackground(True)

        self._app_window.dwarf.onApplyContext.connect(self.on_arch_changed)

        # setting font
        self.font = utils.get_os_monospace_font()
        self.font.setFixedPitch(True)
        self.setFont(self.font)

        self._char_width = QFontMetricsF(self.font).width('#')  # self.fontMetrics().width("#")
        if (self._char_width % 1) < .5:
            self.font.setLetterSpacing(QFont.AbsoluteSpacing, -(self._char_width % 1.0))
            self._char_width -= self._char_width % 1.0
        else:
            self.font.setLetterSpacing(QFont.AbsoluteSpacing, 1.0 - (self._char_width % 1.0))
            self._char_width += 1.0 - (self._char_width % 1.0)

        self._char_height = self.fontMetrics().height()
        self._base_line = self.fontMetrics().ascent()

        self._history = []
        self._lines = []
        self._range = None
        self._longest_bytes = 0
        self._longest_mnemonic = 0

        self._running_disasm = False
        self.capstone_arch = 0
        self.capstone_mode = 0
        self.keystone_arch = 0
        self.keystone_mode = 0
        self.on_arch_changed()

        self._ctrl_colors = {
            'background': QColor('#181818'),
            'foreground': QColor('#666'),
            'jump_arrows': QColor('#444'),
            'jump_arrows_hover': QColor('#ef5350'),
            'divider': QColor('#666'),
            'line': QColor('#111'),
            'selection_fg': QColor(Qt.white),
            'selection_bg': QColor('#ef5350')
        }

        self._jump_color = QColor('#39a')
        self._header_height = 0
        self._ver_spacing = 2

        self._dash_pen = QPen(self._ctrl_colors['jump_arrows'], 2.0, Qt.DashLine)
        self._solid_pen = QPen(self._ctrl_colors['jump_arrows'], 2.0, Qt.SolidLine)
        self._line_pen = QPen(self._ctrl_colors['divider'], 0, Qt.SolidLine)

        self._breakpoint_linewidth = 5
        self._jumps_width = 100

        self.setMouseTracking(True)
        self.current_jump = -1
        self._current_line = -1

        self._display_jumps = True
        self._follow_jumps = True

        self.pos = 0

        # hacky way to let plugins hook this and inject menu actions
        self.menu_extra_menu_hooks = []
        """
        this is one more way for allowing plugin hooks and perform additional operation on the range object
        """
        self.run_default_disassembler = True

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def display_jumps(self):
        return self._display_jumps

    @display_jumps.setter
    def display_jumps(self, value):
        if isinstance(value, bool):
            self._display_jumps = value
            if self._display_jumps:
                self._jumps_width = 100
            else:
                self._jumps_width = 0

    @property
    def follow_jumps(self):
        return self._follow_jumps

    @follow_jumps.setter
    def follow_jumps(self, value):
        if isinstance(value, bool):
            self._follow_jumps = value

    @pyqtProperty('QColor', designable=True)
    def background(self):
        return self._ctrl_colors['background']

    @background.setter
    def background(self, value):
        self._ctrl_colors['background'] = value

    @pyqtProperty('QColor', designable=True)
    def foreground(self):
        return self._ctrl_colors['foreground']

    @foreground.setter
    def foreground(self, value):
        self._ctrl_colors['foreground'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def divider(self):
        return self._ctrl_colors['divider']

    @divider.setter
    def divider(self, value):
        self._ctrl_colors['divider'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def jump_arrows(self):
        return self._ctrl_colors['jump_arrows']

    @jump_arrows.setter
    def jump_arrows(self, value):
        self._ctrl_colors['jump_arrows'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def jump_arrows_hover(self):
        return self._ctrl_colors['jump_arrows_hover']

    @jump_arrows_hover.setter
    def jump_arrows_hover(self, value):
        self._ctrl_colors['jump_arrows_hover'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def line(self):
        return self._ctrl_colors['line']

    @line.setter
    def line(self, value):
        self._ctrl_colors['line'] = QColor(value)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************

    def add_instruction(self, instruction):
        self._lines.append(instruction)
        self.adjust()

    def disassemble(self, dwarf_range, num_instructions=0):
        if self._running_disasm:
            return

        self.onDisassemble.emit(dwarf_range)

        if self.run_default_disassembler:
            self.start_disassemble(dwarf_range, num_instructions=num_instructions)

    def start_disassemble(self, dwarf_range, num_instructions=0):
        self._running_disasm = True
        self._app_window.show_progress('disassembling...')

        self._lines.clear()
        self.viewport().update()

        if len(self._history) == 0 or self._history[len(self._history) - 1] != dwarf_range.start_address:
            self._history.append(dwarf_range.start_address)
            if len(self._history) > 25:
                self._history.pop(0)

        self._longest_bytes = 0
        try:
            capstone = Cs(self.capstone_arch, self.capstone_mode)
            capstone.detail = True
        except CsError:
            self._running_disasm = False
            print('[DisasmView] failed to initialize capstone with %d, %d' % (self.capstone_arch, self.capstone_mode))
            return

        self._range = dwarf_range
        self.disasm_thread = DisassembleThread(self._app_window)
        self.disasm_thread._num_instructions = num_instructions
        self.disasm_thread._range = self._range
        self.disasm_thread._dwarf = self._app_window.dwarf
        self.disasm_thread._capstone = capstone
        self.disasm_thread.onFinished.connect(self._on_disasm_finished)
        self.disasm_thread.start(QThread.HighestPriority)

        self._app_window.asm_panel.show_functions_for_module(hex(dwarf_range.base))

    def _on_disasm_finished(self, instructions):
        if isinstance(instructions, list):
            self._lines = instructions
            self.adjust()

        self._running_disasm = False
        self._app_window.hide_progress()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.adjust()

    def adjust(self):
        for line in self._lines:
            if line:
                if len(line.bytes) > self._longest_bytes:
                    self._longest_bytes = len(line.bytes)
                if len(line.mnemonic) > self._longest_mnemonic:
                    self._longest_mnemonic = len(line.mnemonic)
        self.verticalScrollBar().setRange(0, len(self._lines) - self.visible_lines() + 1)
        self.verticalScrollBar().setPageStep(self.visible_lines())
        self.viewport().update()

    def visible_lines(self):
        """ returns number of lines that fits viewport
        """
        height = self.viewport().height()
        height -= self._header_height + self._char_height + self._ver_spacing
        num_lines = int(ceil(height / (self._char_height + self._ver_spacing)))
        return num_lines + 1

    def pixel_to_line(self, screen_x, screen_y):
        """ helper
        """
        coord_x, coord_y = self.pixel_to_data(screen_x, screen_y)  # pylint: disable=unused-variable
        return coord_y

    def pixel_to_data(self, screen_x, screen_y):
        """ pixel to data coords
        """
        if screen_x < 0:
            screen_x = 0

        top_gap = self._header_height + self._char_height + self._ver_spacing
        data_x = int(ceil(screen_x / int(self._char_width)))
        data_y = int(
            ceil((screen_y - top_gap) /
                 (self._ver_spacing + self._char_height)))
        return (data_x, data_y)

    def read_memory(self, ptr, length=0):
        if self._range is None:
            self._range = Range(Range.SOURCE_TARGET, self._app_window.dwarf)

        init = self._range.init_with_address(ptr, length)
        if init > 0:
            return 1
        self.disassemble(self._range)
        return 0

    # ************************************************************************
    # **************************** Drawing ***********************************
    # ************************************************************************
    def paint_jumps(self, painter):
        # TODO: order by distance
        painter.setRenderHint(QPainter.HighQualityAntialiasing)
        jump_list = [x.address for x in self._lines[self.pos:self.pos + self.visible_lines()] if x.is_jump]
        jump_targets = [x.jump_address for x in self._lines[self.pos:self.pos + self.visible_lines()] if
                        x.address in jump_list]

        drawing_pos_x = self._jumps_width - 10

        for index, line in enumerate(self._lines[self.pos:self.pos + self.visible_lines()]):
            if line.address in jump_list:  # or line.address in jump_targets:
                if line.address == self.current_jump:
                    self._solid_pen.setColor(self._ctrl_colors['jump_arrows_hover'])
                    self._dash_pen.setColor(self._ctrl_colors['jump_arrows_hover'])
                else:
                    self._solid_pen.setColor(self._ctrl_colors['jump_arrows'])
                    self._dash_pen.setColor(self._ctrl_colors['jump_arrows'])
                if line.id == X86_INS_JMP or line.id == X86_INS_CALL:
                    painter.setPen(self._solid_pen)
                else:
                    painter.setPen(self._dash_pen)
                drawing_pos_y = (index + 1) * (self._char_height + self._ver_spacing)
                drawing_pos_y -= self._base_line - (self._char_height * 0.5)

                skip = False

                if line.address not in jump_targets:
                    painter.drawLine(drawing_pos_x + 2, drawing_pos_y, self._jumps_width, drawing_pos_y)
                    if line.jump_address in jump_targets:
                        entry1 = [x for x in self._lines if x.address == line.address]
                        entry2 = [x for x in self._lines if x.address == line.jump_address]
                        if entry1 and entry2:
                            skip = True
                            pos2 = (self._lines.index(entry1[0]) - self._lines.index(entry2[0])) * (
                                        self._char_height + self._ver_spacing)
                            painter.drawLine(drawing_pos_x, drawing_pos_y - pos2, drawing_pos_x, drawing_pos_y)
                            painter.drawLine(drawing_pos_x, drawing_pos_y - pos2, 100, drawing_pos_y - pos2)
                            arrow = QPolygon()
                            arrow.append(QPoint(100, drawing_pos_y - pos2))
                            arrow.append(QPoint(100 - 8, drawing_pos_y - pos2 - 4))
                            arrow.append(QPoint(100 - 8, drawing_pos_y - pos2 + 4))
                            if line.address == self.current_jump:
                                painter.setBrush(self._ctrl_colors['jump_arrows_hover'])
                                painter.setPen(self._ctrl_colors['jump_arrows_hover'])
                            else:
                                painter.setBrush(self._ctrl_colors['jump_arrows'])
                                painter.setPen(self._ctrl_colors['jump_arrows'])
                            painter.drawPolygon(arrow)
                else:
                    skip = True

                if not skip:
                    if line.address > line.jump_address:
                        if line.id == X86_INS_JMP or line.id == X86_INS_CALL:
                            painter.setPen(self._solid_pen)
                        else:
                            painter.setPen(self._dash_pen)
                        painter.drawLine(drawing_pos_x, 5, drawing_pos_x, drawing_pos_y)
                        arrow = QPolygon()
                        arrow.append(QPoint(drawing_pos_x, 0))
                        arrow.append(QPoint(drawing_pos_x + 4, 8))
                        arrow.append(QPoint(drawing_pos_x - 4, 8))
                        if line.address == self.current_jump:
                            painter.setBrush(self._ctrl_colors['jump_arrows_hover'])
                            painter.setPen(Qt.NoPen)
                        else:
                            painter.setBrush(self._ctrl_colors['jump_arrows'])
                            painter.setPen(Qt.NoPen)
                        painter.drawPolygon(arrow)
                    elif line.address < line.jump_address:
                        if line.id == X86_INS_JMP or line.id == X86_INS_CALL:
                            painter.setPen(self._solid_pen)
                        else:
                            painter.setPen(self._dash_pen)
                        painter.drawLine(drawing_pos_x, drawing_pos_y, drawing_pos_x, self.viewport().height() - 5)
                        arrow = QPolygon()
                        arrow.append(QPoint(drawing_pos_x, self.viewport().height()))
                        arrow.append(QPoint(drawing_pos_x + 4, self.viewport().height() - 8))
                        arrow.append(QPoint(drawing_pos_x - 4, self.viewport().height() - 8))
                        if line.address == self.current_jump:
                            painter.setBrush(self._ctrl_colors['jump_arrows_hover'])
                            painter.setPen(Qt.NoPen)
                        else:
                            painter.setBrush(self._ctrl_colors['jump_arrows'])
                            painter.setPen(Qt.NoPen)
                        painter.drawPolygon(arrow)

                drawing_pos_x -= 10
                if drawing_pos_x < 0:
                    break

    def paint_line(self, painter, num_line, line):
        painter.setPen(self._ctrl_colors['foreground'])
        drawing_pos_x = self._jumps_width + self._breakpoint_linewidth + int(self._char_width)
        drawing_pos_y = num_line * (self._char_height + self._ver_spacing)
        drawing_pos_y += self._header_height

        if not line:  # empty line from emu
            return

        num = self._app_window.dwarf.pointer_size * 2
        str_fmt = '{0:08x}'
        if num > 8:
            str_fmt = '{0:016x}'

        if self._uppercase_hex:
            str_fmt = str_fmt.replace('x', 'X')

        painter.drawText(drawing_pos_x, drawing_pos_y, str_fmt.format(line.address))

        is_watched = False
        is_hooked = False

        if self._app_window.dwarf.is_address_watched(line.address):
            is_watched = True

        if line.address in self._app_window.dwarf.hooks:
            is_hooked = True

        if is_watched or is_hooked:
            if is_watched:
                height = self._char_height
                y_pos = drawing_pos_y
                y_pos -= self._base_line - (self._char_height * 0.5)
                y_pos += (self._char_height * 0.5)
                if is_hooked:
                    y_pos -= (self._char_height * 0.5)
                    height *= 0.5
                painter.fillRect(self._jumps_width, y_pos - height, self._breakpoint_linewidth, height,
                                 QColor('greenyellow'))
            if is_hooked:
                height = self._char_height
                y_pos = drawing_pos_y
                y_pos -= self._base_line - (self._char_height * 0.5)
                y_pos += (self._char_height * 0.5)
                if is_watched:
                    height *= 0.5
                painter.fillRect(self._jumps_width, y_pos - height, self._breakpoint_linewidth, height,
                                 QColor('crimson'))

        drawing_pos_x = self._jumps_width + self._breakpoint_linewidth + int(self._char_width) + 1 + int(
            self._char_width)
        drawing_pos_x += (len(str_fmt.format(line.address)) * int(self._char_width))

        painter.setPen(QColor('#444'))
        drawing_pos_x += int(self._char_width)
        for byte in line.bytes:
            painter.drawText(drawing_pos_x, drawing_pos_y, '{0:02x}'.format(byte))
            drawing_pos_x += int(self._char_width) * 3

        drawing_pos_x = self._jumps_width + self._breakpoint_linewidth + (
                    (self._app_window.dwarf.pointer_size * 2) * int(self._char_width)) + (self._longest_bytes + 2) * (
                                    int(self._char_width) * 3)
        painter.setPen(QColor('#39c'))
        painter.drawText(drawing_pos_x, drawing_pos_y, line.mnemonic)
        if line.is_jump:
            painter.setPen(self._jump_color)
        else:
            painter.setPen(self._ctrl_colors['foreground'])

        drawing_pos_x += (self._longest_mnemonic + 1) * int(self._char_width)
        if line.operands and not line.is_jump:
            ops_str = line.op_str.split(', ', len(line.operands) - 1)
            a = 0
            for op in line.operands:
                if op.type == CS_OP_IMM:
                    painter.setPen(QColor('#ff5500'))
                elif op.type == 1:
                    painter.setPen(QColor('#82c300'))
                else:
                    painter.setPen(self._ctrl_colors['foreground'])

                painter.drawText(drawing_pos_x, drawing_pos_y, ops_str[a])
                drawing_pos_x += len(ops_str[a] * int(self._char_width))

                if len(line.operands) > 1 and a < len(line.operands) - 1:
                    painter.setPen(self._ctrl_colors['foreground'])
                    painter.drawText(drawing_pos_x, drawing_pos_y, ', ')
                    drawing_pos_x += 2 * int(self._char_width)
                # if ops_str[a].startswith('0x') and not line.string:
                #    line.string = '{0:d}'.format(int(ops_str[a], 16))
                # drawing_pos_x += (len(ops_str[a]) + 1) * self._char_width
                a += 1
        else:
            if self._follow_jumps and line.is_jump:
                if line.jump_address < line.address:
                    painter.drawText(drawing_pos_x, drawing_pos_y, line.op_str + ' ▲')
                elif line.jump_address > line.address:
                    painter.drawText(drawing_pos_x, drawing_pos_y, line.op_str + ' ▼')
                drawing_pos_x += (len(line.op_str) + 3) * int(self._char_width)
            else:
                painter.drawText(drawing_pos_x, drawing_pos_y, line.op_str)
                drawing_pos_x += (len(line.op_str) + 1) * int(self._char_width)

        if line.symbol_name:
            painter.drawText(drawing_pos_x, drawing_pos_y, '(' + line.symbol_name + ')')
            drawing_pos_x += (len(line.symbol_name) + 1) * int(self._char_width)

        if line.string and not line.is_jump:
            painter.setPen(QColor('#aaa'))
            painter.drawText(drawing_pos_x, drawing_pos_y, ' ; "' + line.string + '"')

    def paint_wait(self, painter):
        """ paint wait popup
        """
        brdr_col = QColor('#444')
        back_col = QColor('#222')
        painter.setPen(QColor('#888'))
        back_rect = self.viewport().rect()
        back_rect.setWidth(back_rect.width() * .2)
        back_rect.setHeight(back_rect.height() * .1)
        screen_x = self.viewport().width() * .5
        screen_x -= back_rect.width() * .5
        screen_y = self.viewport().height() * .5
        screen_y -= back_rect.height() * .5
        painter.fillRect(screen_x - 1, screen_y - 1,
                         back_rect.width() + 2,
                         back_rect.height() + 2, brdr_col)
        painter.fillRect(screen_x, screen_y, back_rect.width(),
                         back_rect.height(), back_col)
        qtext_align = QTextOption(Qt.AlignVCenter | Qt.AlignHCenter)
        text_rect = QRectF(screen_x + 10, screen_y + 10,
                           back_rect.width() - 20,
                           back_rect.height() - 20)
        painter.drawText(text_rect, "Disassembling...", option=qtext_align)

    def paintEvent(self, event):
        if not self.isVisible():
            return

        painter = QPainter(self.viewport())

        if self._running_disasm:
            return self.paint_wait(painter)

        if not self._lines:
            return

        self.pos = self.verticalScrollBar().value()

        # fill background
        painter.fillRect(0, 0, self.viewport().width(), self.viewport().height(), self._ctrl_colors['background'])

        if self._display_jumps:
            painter.setPen(self._ctrl_colors['foreground'])
            drawing_pos_x = self._jumps_width
            self.paint_jumps(painter)
            painter.fillRect(drawing_pos_x, 0, self._breakpoint_linewidth, self.viewport().height(),
                             self._ctrl_colors['jump_arrows'])

        for i, line in enumerate(self._lines[self.pos:self.pos + self.visible_lines()]):
            if i > self.visible_lines():
                break

            if i == self._current_line:
                y_pos = self._header_height + (i * (self._char_height + self._ver_spacing))
                y_pos += (self._char_height * 0.5)
                y_pos -= self._ver_spacing
                painter.fillRect(self._jumps_width + self._breakpoint_linewidth, y_pos - 1, self.viewport().width(),
                                 self._char_height + 2, self._ctrl_colors['line'])
            self.paint_line(painter, i + 1, line)

        painter.setPen(self._line_pen)
        painter.setBrush(Qt.NoBrush)
        drawing_pos_x = self._jumps_width + self._breakpoint_linewidth + int(self._char_width) + int(self._char_width)
        drawing_pos_x += ((self._app_window.dwarf.pointer_size * 2) * int(self._char_width))

        painter.fillRect(drawing_pos_x, 0, 1, self.viewport().height(), self._ctrl_colors['divider'])

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Backspace:
            if len(self._history) > 1:
                self._history.pop(len(self._history) - 1)
                self.read_memory(self._history[len(self._history) - 1])
        elif event.key() == Qt.Key_G and event.modifiers() & Qt.ControlModifier:  # ctrl+g
            self._on_cm_jump_to_address()
        elif event.key() == Qt.Key_M and event.modifiers() & Qt.ControlModifier:  # ctrl+m
            self._on_switch_mode()
        elif event.key() == Qt.Key_P and event.modifiers() & Qt.ControlModifier:  # ctrl+p
            pass  # patch instruction
        elif event.key() == Qt.Key_B and event.modifiers() & Qt.ControlModifier:  # ctrl+b
            pass  # patch bytes
        else:
            # dispatch those to super
            super().keyPressEvent(event)

    def on_arch_changed(self, context=None):
        if self._app_window.dwarf.arch == 'arm64':
            self.capstone_arch = CS_ARCH_ARM64
            self.capstone_mode = CS_MODE_LITTLE_ENDIAN
        elif self._app_window.dwarf.arch == 'arm':
            self.capstone_arch = CS_ARCH_ARM
            context = self._app_window.dwarf.current_context()
            self.capstone_mode = CS_MODE_ARM
            if context is not None and context.is_native_context:
                if context.pc.thumb:
                    self.capstone_mode = CS_MODE_THUMB
        elif self._app_window.dwarf.arch == 'ia32':
            self.capstone_arch = CS_ARCH_X86
            self.capstone_mode = CS_MODE_32
        elif self._app_window.dwarf.arch == 'x64':
            self.capstone_arch = CS_ARCH_X86
            self.capstone_mode = CS_MODE_64
        if self._app_window.dwarf.keystone_installed:
            import keystone.keystone_const as ks
            if self._app_window.dwarf.arch == 'arm64':
                self.keystone_arch = ks.KS_ARCH_ARM64
                self.keystone_mode = ks.KS_MODE_LITTLE_ENDIAN
            elif self._app_window.dwarf.arch == 'arm':
                self.keystone_arch = ks.KS_ARCH_ARM
                self.keystone_mode = ks.KS_MODE_ARM
            elif self._app_window.dwarf.arch == 'ia32':
                self.keystone_arch = ks.KS_ARCH_X86
                self.keystone_mode = ks.KS_MODE_32
            elif self._app_window.dwarf.arch == 'x64':
                self.keystone_arch = ks.KS_ARCH_X86
                self.keystone_mode = ks.KS_MODE_64

    def mouseDoubleClickEvent(self, event):
        loc_x = event.pos().x()
        loc_y = event.pos().y()

        index = self.pixel_to_line(loc_x, loc_y)
        if 0 <= index < self.visible_lines():
            if index + self.pos >= len(self._lines):
                return
            left_side = self._breakpoint_linewidth + self._jumps_width
            addr_width = ((self._app_window.dwarf.pointer_size * 2) * int(self._char_width))
            if loc_x > left_side:
                if loc_x < left_side + addr_width:
                    if self._lines[index + self.pos] and isinstance(self._lines[index + self.pos], Instruction):
                        self.onShowMemoryRequest.emit(
                            hex(self._lines[index + self.pos].address), len(self._lines[index + self.pos].bytes))
                if loc_x > left_side + addr_width:
                    if self._lines[index + self.pos] and isinstance(self._lines[index + self.pos], Instruction):
                        if self._follow_jumps and self._lines[index + self.pos].is_jump:
                            new_pos = self._lines[index + self.pos].jump_address
                            self.read_memory(new_pos)

    # pylint: disable=C0103
    def mouseMoveEvent(self, event):
        """ onmousemove
        """
        loc_x = event.pos().x()
        loc_y = event.pos().y()

        if loc_x > self._breakpoint_linewidth + self._jumps_width:
            self.current_jump = -1
            index = self.pixel_to_line(loc_x, loc_y)

            if 0 <= index < self.visible_lines():
                self._current_line = index
                if index + self.pos < len(self._lines):
                    if isinstance(self._lines[index + self.pos], Instruction):
                        if self._lines[index + self.pos].is_jump:
                            self.current_jump = self._lines[index + self.pos].address

            # self.viewport().update(0, 0, self._breakpoint_linewidth + self._jumps_width, self.viewport().height())
            y_pos = self._header_height + (index * (self._char_height + self._ver_spacing))
            y_pos += (self._char_height * 0.5)
            y_pos -= self._ver_spacing
            self.viewport().update(0, 0, self.viewport().width(), self.viewport().height())

    def mousePressEvent(self, event):
        # context menu
        if event.button() == Qt.RightButton:
            if self._running_disasm:
                return
            self._on_context_menu(event)

    def _on_context_menu(self, event):
        """ build and show contextmenu
        """
        loc_x = event.pos().x()
        loc_y = event.pos().y()

        context_menu = QMenu()

        context_menu.addAction('Jump to address', self._on_cm_jump_to_address)

        # allow mode switch arm/thumb
        if self.capstone_arch == CS_ARCH_ARM:
            if self.capstone_mode == CS_MODE_THUMB:
                mode_str = 'ARM'
            else:
                mode_str = 'THUMB'
            entry_str = '&Switch to {0} mode'.format(mode_str)
            context_menu.addAction(entry_str, self._on_switch_mode)

        if not self._lines:
            # allow jumpto in empty panel
            glbl_pt = self.mapToGlobal(event.pos())
            context_menu.exec_(glbl_pt)
            return

        context_menu.addSeparator()

        index = self.pixel_to_line(loc_x, loc_y)
        address = -1
        if 0 <= index < self.visible_lines():
            if index + self.pos < len(self._lines):
                if isinstance(self._lines[index + self.pos], Instruction):
                    address = self._lines[index + self.pos].address
                    context_menu.addAction(
                        'Copy address', lambda: utils.copy_hex_to_clipboard(address))

                    context_menu.addSeparator()

                    if self._uppercase_hex:
                        str_fmt = '0x{0:X}'
                    else:
                        str_fmt = '0x{0:x}'
                    addr_str = str_fmt.format(address)
                    if self._app_window.watchers_panel:
                        if self._app_window.dwarf.is_address_watched(address):
                            context_menu.addAction(
                                'Remove watcher', lambda: self._app_window.watchers_panel.remove_address(addr_str))
                        else:
                            context_menu.addAction(
                                'Watch address', lambda: self._app_window.watchers_panel.do_addwatcher_dlg(addr_str))
                    if self._app_window.hooks_panel:
                        if address in self._app_window.dwarf.hooks:
                            context_menu.addAction(
                                'Remove hook', lambda: self._app_window.dwarf.dwarf_api('deleteHook', addr_str))
                        else:
                            context_menu.addAction('Hook address', lambda: self._app_window.dwarf.hook_native(addr_str))

        for fcn in self.menu_extra_menu_hooks:
            try:
                fcn(context_menu, address)
            except Exception as e:
                print('failed to add hook menu: %s' % str(e))

        glbl_pt = self.mapToGlobal(event.pos())
        context_menu.exec_(glbl_pt)

    def _on_switch_mode(self):
        if self._range is None:
            return

        if self._app_window.dwarf.arch == 'arm':
            self._lines.clear()

            if self.capstone_mode == CS_MODE_ARM:
                self.capstone_mode = CS_MODE_THUMB
            else:
                self.capstone_mode = CS_MODE_ARM
            self.disassemble(self._range)

    def _on_cm_jump_to_address(self):
        ptr, _ = InputDialog.input_pointer(self._app_window)
        if ptr > 0:
            self.read_memory(ptr)
