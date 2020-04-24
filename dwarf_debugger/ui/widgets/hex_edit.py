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

import sys
from math import ceil, floor

import pyperclip
# pylint: disable=unused-import #temp selection code is missing
from PyQt5.QtCore import (Qt, QObject, pyqtSignal, QRect, QRectF, QTimer,
                          QPoint, pyqtProperty)
from PyQt5.QtGui import (QFont, QPainter, QColor, QTextOption,
                         QCursor, QPolygon, QFontMetricsF)
from PyQt5.QtWidgets import (QAbstractScrollArea, QMenu)

from dwarf_debugger.ui.dialogs.dialog_input import InputDialog
from dwarf_debugger.lib import utils

from dwarf_debugger.ui.widgets.utils.caret import Caret
from dwarf_debugger.ui.widgets.utils.selection import Selection

# pylint: disable=too-many-lines
# pylint: disable=too-many-statements
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-public-methods


# pylint: disable=C0103



# pylint: disable=C0103


class HighlightExistsError(Exception):
    """Raised when highlight exists on address"""


# pylint: disable=C0103
class HighLight(QObject):
    """ Highlight

        what:   default='attention'
                allowed='attention', 'breakpoint', 'changed', 'edited',\
                        'patched', 'pointer', 'search', 'string'
                'attention, changed': are removed after x sec

        offset: address
        length: len bytes to highlight

        usage:
            hexedit.add_highlight(Highlight('breakpoint', 0x482358a, 8))
            hexedit.remove_highlight(address) # it checks if address is in addr+len
            hexedit.clear_highlights()
    """

    def __init__(self, what='attention', offset=0, length=0):
        super(HighLight, self).__init__()

        self.what = what
        self.offset = offset
        self.length = length


# pylint: disable=C0103
class HexEditor(QAbstractScrollArea):
    """ HexEdit Control

        Signals:
            selectionChanged()
            viewChanged()
            dataChanged(position, length)

        Prefs:
            * (default named first)
            dwarf_ui_hexstyle: ('upper', 'lower')
            dwarf_ui_hexedit_hover: ('True', 'False') - Hover current Line
            dwarf_ui_hexedit_bpl: Number of Bytes per Line

    """

    # pylint: disable=too-many-instance-attributes

    selectionChanged = pyqtSignal(name='selectionChanged')
    viewChanged = pyqtSignal(name='viewChanged')
    dataChanged = pyqtSignal(int, int, name='dataChanged')
    statusChanged = pyqtSignal(str, name='statusChanged')

    def __init__(self, app, debug_panel=None):
        super(HexEditor, self).__init__()

        self.setObjectName(self.__class__.__name__)
        self.setAttribute(Qt.WA_StyledBackground)

        self._background = None

        self._ctrl_colors = {
            'background': QColor('#181818'),
            'foreground': QColor('#666'),
            'header_bg': QColor('#212121'),
            'byte_col_1': QColor('#444'),
            'byte_col_2': QColor('#333'),
            'divider': QColor('#333'),
            'linecol': QColor('#222'),
            'selection_fg': QColor(Qt.white),
            'selection_bg': QColor('#ef5350')
        }

        self._highlight_colors = {
            'attention': QColor('#ff3388'),
            'changed': QColor('#ff3388'),
            'breakpoint': QColor('#009688'),
            'watchpoint': QColor('#4fc3f7'),
            'edited': QColor('#ff5722'),
            'patched': QColor('#ff5722'),
            'string': QColor('#8bc34a'),
            'pointer': QColor('#ff9900'),
            'search': QColor('#fc3')
        }

        self.app = app

        self.debug_panel = debug_panel
        self.data = None

        self.base = 0

        # allow edit
        self._read_only = False  # todo: add something to range

        # QAbstractScrollArea stuff
        self.setFocusPolicy(Qt.StrongFocus)
        self.setMouseTracking(True)  # keep: required for mousecursor on header
        self.viewport().setCursor(Qt.IBeamCursor)

        # reset scroll
        self.verticalScrollBar().setRange(0, 0)
        self.horizontalScrollBar().setRange(0, 0)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)  # temp off
        self.pos = 0

        # setting font
        self.font = utils.get_os_monospace_font()
        self.font.setFixedPitch(True)
        self.setFont(self.font)

        # constants
        self._hex_chars = "0123456789abcdef"
        self._min_bple = 8
        self._max_bple = 11
        self._hor_spacing = 10
        self._ver_spacing = 2
        self._is_64bit_addr = True

        # get preferences
        _prefs = self.app.prefs
        self._hex_style = _prefs.get('dwarf_ui_hexstyle', 'upper')
        if self._hex_style != 'upper' and self._hex_style != 'lower':
            self._hex_style = 'upper'

        self._hover_lines = _prefs.get('dwarf_ui_hexedit_hover',
                                       'True') == 'True'

        try:
            self._pref_bpl = int(_prefs.get('dwarf_ui_hexedit_bpl', 16))
        except ValueError:
            self._pref_bpl = 16

        if self._pref_bpl not in [
            1 << e for e in range(self._min_bple, self._max_bple)
        ]:
            self._pref_bpl = 16

        self._bytes_per_line = self._pref_bpl

        self._char_width = QFontMetricsF(self.font).width('#')  # self.fontMetrics().width("#")
        if (self._char_width % 1) < .5:
            self.font.setLetterSpacing(QFont.AbsoluteSpacing, -(self._char_width % 1.0))
            self._char_width -= self._char_width % 1.0
        else:
            self.font.setLetterSpacing(QFont.AbsoluteSpacing, 1.0 - (self._char_width % 1.0))
            self._char_width += 1.0 - (self._char_width % 1.0)

        self._char_height = self.fontMetrics().height()
        self._base_line = self.fontMetrics().ascent()

        # drawing positions
        self._addr_chr = 8
        if self._is_64bit_addr:
            self._addr_chr += 8

        # precalcs
        self._line_width = 1
        self._header_padding = 5
        self._header_height = self._char_height + (2 * self._header_padding)

        self._col_div = self._hor_spacing + self._line_width + self._hor_spacing

        self._offset_start = self._hor_spacing
        self._offset_width = self._char_width * self._addr_chr

        self._hex_start = self._offset_start + self._offset_width + self._col_div
        self._hex_width = self.bytes_per_line * (
                3 * self._char_width) - self._char_width

        self._ascii_start = self._hex_start + self._hex_width + self._col_div
        self._ascii_width = self.bytes_per_line * self._char_width

        # paint related
        self._draw_sep_lines = True
        self._dual_color_bytes = True
        self._hovered_line = -1

        # selection
        self._is_selecting = False
        self.selection = Selection(active=False)

        # caret
        self._caret = Caret('hex', 0, 0)
        self._caret.posChanged.connect(self.caret_pos_changed)
        self._blink = False

        # Caret blinking
        self._caret_timer = QTimer()
        self._caret_timer.timeout.connect(self.update_caret)
        self._caret_timer.setInterval(500)
        self._caret_timer.start()

        # highlights
        self._highlights = []
        self._highlight_timer = QTimer()
        self._highlight_timer.setSingleShot(True)
        self._highlight_timer.timeout.connect(self._clear_highlights)
        self._highlight_timer.setInterval(1000)

        # error popup stuff
        self._error_message = ''
        self._error_timer = QTimer()
        self._error_timer.setSingleShot(True)
        self._error_timer.timeout.connect(self._clear_error)
        self._error_timer.setInterval(2500)

        # refit scrollbars
        self.adjust()

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    # used to allow theming
    # pylint: disable=pointless-string-statement
    """ Example: (from black_style.qss)

        HexEditor {
            qproperty-background: #000;
            qproperty-foreground: #666;
            qproperty-header: #111;
            qproperty-divider: #222;
            qproperty-selfg: #bbb;
            qproperty-selbg: #ef5350;
            qproperty-line: #111;
        }
    """

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
    def header(self):
        return self._ctrl_colors['header_bg']

    @header.setter
    def header(self, value):
        self._ctrl_colors['header_bg'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def divider(self):
        return self._ctrl_colors['divider']

    @divider.setter
    def divider(self, value):
        self._ctrl_colors['divider'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def selfg(self):
        return self._ctrl_colors['selection_fg']

    @selfg.setter
    def selfg(self, value):
        self._ctrl_colors['selection_fg'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def selbg(self):
        return self._ctrl_colors['selection_bg']

    @selbg.setter
    def selbg(self, value):
        self._ctrl_colors['selection_bg'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def line(self):
        return self._ctrl_colors['linecol']

    @line.setter
    def line(self, value):
        self._ctrl_colors['linecol'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def byte(self):
        return self._ctrl_colors['byte_col_1']

    @byte.setter
    def byte(self, value):
        self._ctrl_colors['byte_col_1'] = QColor(value)

    @pyqtProperty('QColor', designable=True)
    def bytealt(self):
        return self._ctrl_colors['byte_col_2']

    @bytealt.setter
    def bytealt(self, value):
        self._ctrl_colors['byte_col_2'] = QColor(value)

    # getter setter
    @property
    def is_64bit_address(self):
        """ Offset display
        """
        return self._is_64bit_addr

    @is_64bit_address.setter
    def is_64bit_address(self, value):
        if isinstance(value, bool):
            self._is_64bit_addr = value
            self.viewChanged.emit()

    @property
    def bytes_per_line(self):
        """ return number of bytes in line
        """
        return self._bytes_per_line

    @bytes_per_line.setter
    def bytes_per_line(self, value):
        if isinstance(value, int):
            self._bytes_per_line = value
            self._hex_width = self.bytes_per_line * (
                    3 * self._char_width) - self._char_width
            self._ascii_start = self._hex_start + self._hex_width + self._col_div
            self._ascii_width = self.bytes_per_line * self._char_width
            self.viewport().update()
            self.viewChanged.emit()

    @property
    def caret(self):
        """ Get
        """
        return self._caret

    @caret.setter
    def caret(self, value):
        """ Set
        """
        self.viewport().update()
        self._caret.update(value)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def number_of_lines(self):
        """ returns number of total lines
        """
        if self.data is None:
            return 0

        return int(len(self.data) / self.bytes_per_line)

    def visible_columns(self):
        """ returns visible cols
            not used atm - no hor scroll
        """
        ret = int(ceil(float(self.viewport().width() / self._char_width)))
        return ret

    def number_of_chars(self):
        """ returns number of chars in row
            not used atm - no hor scroll
        """
        ret = (self.bytes_per_line * 3) + self.bytes_per_line + (
                (self._offset_width - self._offset_start) / self._char_width) * 4
        # ret = self._bytes_per_line * 4
        return ret

    @staticmethod
    def to_ascii(bytes_):
        """ byte to ascii
        """
        return "".join([
            chr(x) if 0x20 <= x <= 0x7e or x == 0xff else "."
            for x in bytes_
        ])

    def get_lines(self, pos=0):
        """ get bytes from data
        """
        if self.data is None:
            return None

        while pos < len(self.data) - self.bytes_per_line:
            yield (pos, self.bytes_per_line,
                   self.to_ascii(self.data[pos:pos + self.bytes_per_line]))
            pos += self.bytes_per_line

        yield (pos, len(self.data) - pos, self.to_ascii(self.data[pos:]))

    def get_bytes(self, count=1):
        """ get bytes from data
        """
        return self.data[self._caret.position:self._caret.position + count]

    def visible_lines(self):
        """ returns number of lines that fits viewport
        """
        height = self.viewport().height()
        height -= self._header_height + self._char_height + self._ver_spacing
        num_lines = int(ceil(height / (self._char_height + self._ver_spacing)))
        return num_lines + 1

    def index_to_line(self, index):
        """ helper
        """
        coord_x, coord_y = self.index_to_coords(index)
        loc_x, loc_y = self.data_to_pixel(coord_x, coord_y)  # pylint: disable=unused-variable
        loc_y -= self._header_height + self._char_height + self._ver_spacing
        loc_y = loc_y / (self._char_height + self._ver_spacing)
        return int(loc_y)

    def pixel_to_line(self, screen_x, screen_y):
        """ helper
        """
        coord_x, coord_y = self.pixel_to_data(screen_x, screen_y)  # pylint: disable=unused-variable
        return coord_y

    def pixel_to_caret(self, pos_x, pos_y):
        """ screen to caretpos
        """
        if self.data is None:
            return None
        # pos in offset
        if pos_x <= (self._hex_start - self._char_width):
            return None

        # pos in header
        if pos_y <= self._header_height:
            return None

        index = 0
        mode = 'hex'

        # in hex
        if pos_x <= self._ascii_start - self._col_div:
            column, row = self.pixel_to_data(pos_x - self._hex_start, pos_y)
            if column < 0 or row < 0:
                return None
            line = int(ceil(column - (column / 3)))
            index = int(
                floor(self.pos + line / 2 + row * self.bytes_per_line))
            if index > len(self.data):
                index = len(self.data)
            mode = 'hex'

        # in ascii
        if pos_x > self._ascii_start - self._col_div:
            column, row = self.pixel_to_data(pos_x - self._ascii_start, pos_y)
            if column < 0 or row < 0:
                return None
            line_index = int(ceil(column % self.bytes_per_line))
            index = int(
                floor(self.pos + line_index + row * self.bytes_per_line))
            if index > len(self.data):
                index = len(self.data)
            mode = 'ascii'

        return Caret(mode, index, 0)

    def pixel_to_data(self, screen_x, screen_y):
        """ pixel to data coords
        """
        if screen_x < 0:
            screen_x = 0

        top_gap = self._header_height + self._char_height + self._ver_spacing
        data_x = int(ceil(screen_x / self._char_width))
        data_y = int(
            ceil((screen_y - top_gap) /
                 (self._ver_spacing + self._char_height)))
        return (data_x, data_y)

    def data_to_pixel(self, data_x, data_y):
        """ data to pixel coords
        """
        top_gap = self._header_height + self._char_height + self._ver_spacing
        screen_x = int(ceil(data_x * self._char_width))
        screen_y = int(ceil(data_y * (self._char_height + self._ver_spacing)))
        screen_y += top_gap
        return (screen_x, screen_y)

    def index_to_coords(self, index):
        """ returns index in data as x,y
        """
        coord_x = int(index % self.bytes_per_line)
        coord_y = int(index / self.bytes_per_line)
        return (coord_x, coord_y)

    def index_to_hexcol(self, index):
        """ returns index as screen_x, screen_y in hexcolumn
        """
        coord_x, coord_y = self.index_to_coords(index - self.pos)
        screen_x = int(
            floor((coord_x * (self._char_width * 3)) + self._hex_start))
        screen_y = self._header_height + self._char_height + self._ver_spacing
        screen_y += coord_y * (self._char_height + self._ver_spacing)
        return (screen_x, screen_y)

    def index_to_asciicol(self, index):
        """ returns index as screen_x, screen_y in asciicolumn
        """
        coord_x, coord_y = self.index_to_coords(index - self.pos)
        screen_x = int(floor(coord_x * self._char_width) + self._ascii_start)
        screen_y = self._header_height + self._char_height + self._ver_spacing
        screen_y += coord_y * (self._char_height + self._ver_spacing)
        return (screen_x, screen_y)

    def caret_to_hexcol(self, caret):
        """ returns screenpos as qrect of caret in hex
        """
        hex_cx, hex_cy = self.index_to_hexcol(caret.position)
        hex_cx += (caret.nibble * self._char_width) + 1
        hex_cy -= self._base_line
        hex_rect = QRect(hex_cx - 1, hex_cy, 1, self._char_height)
        return hex_rect

    def caret_to_asciicol(self, caret):
        """ returns screenpos as qrect of caret in ascii
        """
        ascii_cx, ascii_cy = self.index_to_asciicol(caret.position)
        ascii_cy -= self._base_line
        ascii_rect = QRect(ascii_cx - 1, ascii_cy, 1, self._char_height)
        return ascii_rect

    def data_at_caret(self, caret):
        """ returns hex,byte at current caretpos
        """
        cur_byte = self.data[caret.position]
        hexcode = "{:02x}".format(cur_byte)
        hex_char = hexcode[caret.nibble]
        return (hex_char, cur_byte)

    def update_caret(self):
        """ caret blinking
        """
        if self.data is None:
            return

        if not self.isVisible():
            return

        if not self.hasFocus():
            return

        self._blink = not self._blink
        self.viewport().update(self.caret_to_hexcol(self.caret))

    def _addr_width_changed(self):
        if self._is_64bit_addr:
            self._offset_width = max(
                len('OFFSET (X)') * self._char_width, 16 * self._char_width)
        else:
            self._offset_width = max(
                len('OFFSET (X)') * self._char_width, 8 * self._char_width)

        self._hex_start = self._offset_start + self._offset_width + self._col_div
        self._ascii_start = self._hex_start + self._hex_width + self._col_div

    def adjust(self):
        """ scroll adjusting
        """
        self.horizontalScrollBar().setRange(
            0,
            self.number_of_chars() - self.visible_columns() + 1)
        self.horizontalScrollBar().setPageStep(self.visible_columns())
        self.verticalScrollBar().setRange(
            0,
            self.number_of_lines() - self.visible_lines() + 2)
        self.verticalScrollBar().setPageStep(self.visible_lines())

    def read_pointer(self):
        """ reads pointer from data
        """

        if self.data is None:
            return None

        # todo: little/big endian
        ptr_size = self.app.dwarf.pointer_size
        start = self.caret.position
        end = self.caret.position + ptr_size
        ptr = int.from_bytes(self.data[start:end], sys.byteorder)
        is_valid_ptr = self.app.dwarf.dwarf_api('isValidPointer', ptr)
        if ptr > 0 and is_valid_ptr:
            return ptr

        return None

    def modify_data(self, text):
        """ change data
        """
        current_byte = self.data[self.caret.position]
        _byte = 0

        # caret is hextype so allow nibble editing
        if self.caret.mode == 'hex':
            if self.caret.nibble == 1:
                _byte = (current_byte & 0xf0) | self._hex_chars.index(text)
                self.caret.nibble = 0
            else:
                _byte = (current_byte & 0x0f) | (
                        self._hex_chars.index(text) << 4)
                self.caret.nibble = 1
        # caret is asciitype try byteconv
        elif self.caret.mode == 'ascii':
            try:
                _byte = int(bytearray(text, 'utf8')[0])
            except ValueError:
                self.display_error('something is wrong')
                return
        else:
            return

        # change byte in data
        data_bt = bytearray(self.data)
        data_bt[self.caret.position] = _byte
        self.data = bytes(data_bt)

        # emit datachanged
        self.dataChanged.emit(self.caret.position, 1)

        # add highlight
        try:
            is_highlight = self.is_highlighted(self.caret.position + self.base)
            if not is_highlight:
                self.add_highlight(
                    HighLight('edited', self.caret.position + self.base, 1))
        except HighlightExistsError:
            pass

        # move cursor when and repaint
        if self.caret.mode == 'hex':
            # dont move to next byte when in nibbleedit
            if self.caret.nibble == 0:
                self.caret.move_right(len(self.data))
        elif self.caret.mode == 'ascii':
            self.caret.move_right(len(self.data))
        self._force_repaint(True)

    def get_highlight(self, address):
        """ Checks if given pos is already colored
            returns False or highlighttype
        """
        is_highlight = [
            x for x in self._highlights
            if x.offset <= address <= x.offset + x.length - 1
        ]
        if is_highlight:
            if is_highlight[0]:
                return is_highlight[0]

        return None

    def is_highlighted(self, address):
        """ Checks if given pos is already colored
            returns False or highlighttype
        """
        is_highlight = [
            x for x in self._highlights
            if x.offset <= address <= x.offset + x.length - 1
        ]
        if is_highlight:
            if is_highlight[0]:
                return is_highlight[0].what

        return False

    def add_highlight(self, highlight):
        """ Add highlight

            highlight = Highlight('what', addr, len)

            Raises 'HighlightExistsError' if an highlight at given Address exists
        """
        is_highlight = self.is_highlighted(highlight.offset)

        # no highlight exists add one
        # is given highlight is a temp highlight its added too (autoremoved later anyway)
        if not is_highlight or highlight.what == 'changed' or highlight.what == 'attention':
            self._highlights.append(highlight)
        else:
            error_msg = ('Existing Highlight at 0x{0:x} type {1}'.format(
                highlight.offset, is_highlight))
            raise HighlightExistsError(error_msg)

        self.viewChanged.emit()
        self.viewport().update()
        if highlight.what == 'changed' or highlight.what == 'attention':
            self._highlight_timer.start()

    def _clear_highlights(self):
        """ handles temporary highlights
            'changed', 'attention'
        """
        self._highlights = [
            x for x in self._highlights
            if x.what != 'changed' and x.what != 'attention'
        ]
        self.viewChanged.emit()
        self.viewport().update()

    def remove_highlight(self, address):
        """ Removes highlight at address
        """
        self._highlights = [
            x for x in self._highlights
            if x.offset > address >= x.offset + x.length
        ]
        self.viewChanged.emit()
        self.viewport().update()

    def remove_highlights(self, highlight_type):
        """ Removes all highlights with given type
        """
        self._highlights = [
            x for x in self._highlights if x.what != highlight_type
        ]
        self.viewChanged.emit()
        self.viewport().update()

    def clear_highlights(self):
        """ Clear all highlights
        """
        self._highlights.clear()
        self.viewChanged.emit()
        self.viewport().update()

    def display_error(self, error_msg):
        """ Displays ErrorPopup in view
        """
        self._error_timer.stop()
        self._error_message = error_msg
        self._force_repaint(True)
        self._error_timer.start()

    def _force_repaint(self, notify=False):
        """ updates viewport
            notify: emit viewChanged() signal
        """
        self.viewport().update()
        if notify:
            self.viewChanged.emit()

    def make_c_array(self, start, end):
        """ makes an c array from data used by copy as c code
        """
        c_code = '// generated by dwarf\nunsigned char rawData[{0}] = '.format(
            end - start)
        c_code += '{\n\t'

        for i in range(start, end):
            if (i - start) and ((i - start) % 12 == 0):
                c_code = c_code[0:-1]  # remove last space
                c_code += '\n\t'  # next line

            if self._hex_style == 'upper':
                c_code += '0x{0:02X}, '.format(self.data[i])
            else:
                c_code += '0x{0:02x}, '.format(self.data[i])

        # remove last ', '
        c_code = c_code[0:-2]
        c_code += '\n};'

        return c_code

    def make_py_array(self, start, end):
        """ makes python array from data
        """
        py_code = '# generated by dwarf\nraw_data = [\n\t'

        for i in range(start, end):
            if (i - start) and ((i - start) % 12 == 0):
                py_code = py_code[0:-1]  # remove last space
                py_code += '\n\t'  # next line

            if self._hex_style == 'upper':
                py_code += '0x{0:02X}, '.format(self.data[i])
            else:
                py_code += '0x{0:02x}, '.format(self.data[i])

        # remove last ', '
        py_code = py_code[0:-2]
        py_code += '\n]'

        return py_code

    def make_js_array(self, start, end):
        """ makes js array from data
        """
        js_code = '// generated by dwarf\nvar rawData = [\n\t'

        for i in range(start, end):
            if (i - start) and ((i - start) % 12 == 0):
                js_code = js_code[0:-1]  # remove last space
                js_code += '\n\t'  # next line

            if self._hex_style == 'upper':
                js_code += '0x{0:02X}, '.format(self.data[i])
            else:
                js_code += '0x{0:02x}, '.format(self.data[i])

        # remove last ', '
        js_code = js_code[0:-2]
        js_code += '\n];'

        return js_code

    def set_data(self, data, base=0, offset=None):
        """ Set new Data
        """
        self.data = data
        self.base = base
        self.adjust()

        if offset is not None:
            self.setFocus()
            self.caret.position = int(ceil(offset))
            self.adjust()
            # scroll position in middle when jump to or something
            line = self.index_to_line(self.caret.position)
            scroll_y = self.verticalScrollBar().value()
            if line >= scroll_y:
                self.verticalScrollBar().setValue(int(line - (self.visible_lines() / 2)))
            if line < scroll_y:
                self.verticalScrollBar().setValue(int(line + (self.visible_lines() / 2)))

            if self._hover_lines:
                self._hovered_line = int(ceil(self.visible_lines() / 2))

            # add a temp attention highlight
            self.add_highlight(HighLight('attention', base + offset, 1))

        self.viewChanged.emit()

    # ************************************************************************
    # **************************** Events  ***********************************
    # ************************************************************************
    # pylint: disable=C0103, W0613
    def resizeEvent(self, event):
        """ onresize
        """
        width = self.width()
        columns = max(8, int((((width - (2 * self._hor_spacing)) / self._char_width) - self._max_bple) / 32) * 8)
        if columns < 8:
            columns = 8

        self.bytes_per_line = columns

        self.adjust()

    # pylint: disable=C0103
    def paintEvent(self, event):
        """ onpaint
        """
        self.do_paint(event)

    # pylint: disable=C0103, W0612
    def mousePressEvent(self, event):
        """ onmousedown
        """

        # context menu
        if event.button() == Qt.RightButton and self.debug_panel is not None:
            self._on_context_menu(event)
            return

        # empty
        if self.data is None:
            return

        # not left then nothing todo
        if event.button() != Qt.LeftButton:
            return

        loc_x = event.pos().x()
        loc_y = event.pos().y()
        if 0 <= loc_x <= self._offset_width:
            if 0 <= loc_y <= self._header_height:
                if self._hex_style == 'upper':
                    self._hex_style = 'lower'
                else:
                    self._hex_style = 'upper'
                self.app.prefs.put('dwarf_ui_hexstyle', self._hex_style)
                self.update()

        if loc_y <= self._header_height:
            return

        cur = self.pixel_to_caret(loc_x, loc_y)
        if cur is not None:
            if not self._is_selecting:
                self._is_selecting = True
                self.selection.active = True

            if self.selection.active:
                self.selection.active = False
                self.selection.start = self.selection.end = cur.position
                self.viewport().update()
            self._blink = False
            self.viewport().update(self.caret_to_asciicol(self.caret))
            self.viewport().update(self.caret_to_hexcol(self.caret))
            self.caret = cur

    # pylint: disable=C0103
    def mouseMoveEvent(self, event):
        """ onmousemove
        """
        loc_x = event.pos().x()
        loc_y = event.pos().y()

        # mouse in header - change to arrow
        if 0 <= loc_y <= self._header_height:
            if self._hover_lines:
                self._hovered_line = -1
                self.viewport().update(
                    QRect(0, 0,
                          self.viewport().width(),
                          (self._char_height * 3) + self._header_height))
            self.viewport().setCursor(Qt.ArrowCursor)
        else:
            self.viewport().setCursor(Qt.IBeamCursor)

        if self.data is None:
            return

        if loc_y > self._header_height:
            if self._hover_lines:
                self._hovered_line = self.pixel_to_line(loc_x, loc_y)
                self.viewport().update()  # todo: optimize redraw rect

        if self.data:
            show = False
            if loc_y > self._header_height + self._ver_spacing:
                if (self._hex_start - self._hor_spacing) < loc_x < self._ascii_start:
                    coord_x, coord_y = self.pixel_to_data(
                        loc_x - self._hex_start, loc_y)
                    line = int(ceil(coord_x - (coord_x / 3)))
                    index = int(
                        floor(self.pos + line / 2
                              + coord_y * self.bytes_per_line))
                    show = True
                elif self._ascii_start < loc_x < self._ascii_start + self._ascii_width:
                    coord_x, coord_y = self.pixel_to_data(
                        loc_x - self._ascii_start, loc_y)
                    line = int(ceil(coord_x % self.bytes_per_line))
                    index = int(
                        floor(self.pos + line +
                              coord_y * self.bytes_per_line))
                    show = True

                if show:
                    if self.is_64bit_address:
                        txt = 'Address: 0x{0:016X}'.format(index + self.base)
                    else:
                        txt = 'Address: 0x{0:08X}'.format(index + self.base)
                    if txt:
                        self.statusChanged.emit(txt)

        if self._is_selecting:
            self.selection.start = self.caret.position
            new_caret = self.pixel_to_caret(loc_x, loc_y)
            if new_caret is None:
                return
            self.selection.end = new_caret.position
            if self.selection.end > len(self.data):
                self.selection.end = len(self.data)
            self.selection.active = True
            self._force_repaint(True)
            self.selectionChanged.emit()

    # pylint: disable=C0103
    def mouseReleaseEvent(self, event):
        """ onmouseup
        """
        if self._is_selecting:
            self._is_selecting = False
            self.selection.active = False
        cur = self.pixel_to_caret(event.pos().x(), event.pos().y())
        if cur is not None:
            self.caret = cur
            self.viewport().update(self.caret_to_hexcol(self.caret))

    # pylint: disable=C0103
    def keyPressEvent(self, event):
        """ onkeydown
        """
        key = event.key()
        mod = event.modifiers()
        text = event.text()

        # caret movement
        if key == Qt.Key_Right:
            self.caret.move_right(len(self.data))
        elif key == Qt.Key_Left:
            self.caret.move_left()
        elif key == Qt.Key_Up:
            self.caret.move_up(self.bytes_per_line)
        elif key == Qt.Key_Down:
            self.caret.move_down(self.bytes_per_line, len(self.data))
        elif key == Qt.Key_PageUp:
            self.caret.move_up(self.visible_lines() * self.bytes_per_line)
        elif key == Qt.Key_PageDown:
            self.caret.move_down(self.visible_lines() * self.bytes_per_line,
                                 len(self.data))
        elif key == Qt.Key_Home:
            self.caret.position = 0
        elif key == Qt.Key_End:
            self.caret.position = len(self.data)

        if self.debug_panel is not None:
            if key == Qt.Key_G and mod & Qt.ControlModifier:  # CTRL + G
                self.debug_panel.on_cm_jump_to_address()
            elif key == Qt.Key_D and mod & Qt.ControlModifier:  # CTRL + D
                self.on_cm_show_asm()
            if not mod & Qt.ControlModifier:
                if text.lower() in self._hex_chars:
                    if not self._read_only and text:
                        self.modify_data(text.lower())
                elif text.isalpha() or text.isdigit() or text.isspace():
                    if not self._read_only:
                        if self.caret.mode == 'ascii':
                            self.modify_data(text)

        # repaint
        self._force_repaint()

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def caret_pos_changed(self):
        """ handles caret position changed signal
        """
        # scroll to new pos if needed
        line = self.index_to_line(self.caret.position)
        scroll_y = self.verticalScrollBar().value()
        if line >= (scroll_y + self.visible_lines()):
            self.verticalScrollBar().setValue(line
                                              - (self.visible_lines() - 1))
        if line < scroll_y:
            self.verticalScrollBar().setValue(line)

        self._force_repaint()

    def _clear_error(self):
        """ resets error
        """
        self._error_timer.stop()
        self._error_message = ''
        self._force_repaint(True)

    # pylint: disable=W0613
    def _on_context_menu(self, event):
        """ build and show contextmenu
        """
        context_menu = QMenu()

        loc_x = event.pos().x()
        loc_y = event.pos().y()

        show = False
        address = 0
        addr_str = '0'

        if loc_y > self._header_height + self._ver_spacing:
            # cursor in hex
            index = 0
            if (self._hex_start - self._hor_spacing) < loc_x < self._ascii_start:
                coord_x, coord_y = self.pixel_to_data(
                    loc_x - self._hex_start, loc_y)
                line = int(ceil(coord_x - (coord_x / 3)))
                index = int(
                    floor(self.pos + line / 2 +
                          coord_y * self.bytes_per_line))
                show = True
            elif (self._ascii_start + self._ascii_width) > loc_x > self._ascii_start:
                # elif loc_x > self._ascii_start and
                # loc_x < (self._ascii_start + self._ascii_width):
                coord_x, coord_y = self.pixel_to_data(
                    loc_x - self._ascii_start, loc_y)
                line = int(ceil(coord_x % self.bytes_per_line))
                index = int(
                    floor(self.pos + line +
                          coord_y * self.bytes_per_line))
                show = True

            if show:
                address = self.base + index
                addr_str = hex(address)

                context_menu.addAction(addr_str)
                context_menu.addSeparator()

                context_menu.addAction("&Disassemble", self.on_cm_show_asm)
                context_menu.addAction("&Dump to file", self.on_cm_dump_to_file)
                context_menu.addSeparator()

                context_menu.addAction("Follow &pointer", self.on_cm_follow_pointer)
                context_menu.addSeparator()

                if self.app.watchpoints_panel:
                    if self.app.dwarf.is_address_watched(address):
                        context_menu.addAction(
                            'Remove watchpoint', lambda: self.app.watchpoints_panel.remove_address(addr_str))
                    else:
                        context_menu.addAction(
                            'Watch address', lambda: self.app.watchpoints_panel.do_addwatchpoint_dlg(addr_str))
                if self.app.breakpoints_panel:
                    if address in self.app.dwarf.breakpoints:
                        context_menu.addAction(
                            'Remove breakpoint', lambda: self.app.dwarf.dwarf_api('deleteBreakpoint', addr_str))
                    else:
                        context_menu.addAction('Breakpoint address', lambda: self.app.dwarf.breakpoint_native(addr_str))

                context_menu.addSeparator()

        # write_string = context_menu.addAction("&Write string")
        # menu_actions[write_string] = self.on_cm_writestring

        # hide copy section when nothing selected
        if self.selection.start != self.selection.end:
            context_menu.addAction("&Copy", self.on_cm_copy)

            copy_as_content = QMenu("Copy as", context_menu)
            copy_as_content.addAction('C Source')
            copy_as_content.addAction('Python Source')
            copy_as_content.addAction('JS Source')
            copy_as_content.triggered.connect(self.on_cm_copy_as)

            context_menu.addMenu(copy_as_content)

            context_menu.addSeparator()

        if show:
            context_menu.addAction('&Copy address', lambda: utils.copy_hex_to_clipboard(hex(self.base + index)))

        context_menu.addAction("&Jump to address", self.debug_panel.on_cm_jump_to_address)

        if not context_menu.isEmpty():
            context_menu.exec_(QCursor.pos())

    def on_cm_bookmark(self):
        """ ContextMenu Create Bookmark
        """
        ptr = self.base + self.caret.position
        self.app.on_add_bookmark(ptr)

    def on_cm_follow_pointer(self):
        """ ContextMenu FollowPointer
        """
        if self.data is None:
            return

        ptr = self.read_pointer()
        if ptr is not None:
            self.debug_panel.jump_to_address(ptr)
        else:
            self.display_error('Unable to read pointer at location.')

    def on_cm_breakpoint_address(self):
        """ ContextMenu BreakpointAddress
        """
        ptr = self.base + self.caret.position
        self.app.dwarf.breakpoint_native(input_=hex(ptr))

    def on_cm_show_asm(self):
        """ ContextMenu Disassemble
        """
        ptr = self.base + self.caret.position
        self.debug_panel.jump_to_address(ptr, 1)

    def on_cm_dump_to_file(self):
        """ ContextMenu DumpToFile
        """
        accept, _input = InputDialog.input(hint='length of bytes to dump', placeholder='1024')

        if not accept:
            return

        try:
            _len = int(_input)
        except:
            self.display_error('Invalid length provided')
            _len = 0
        if _len > 0:
            self.debug_panel.dump_data(self.caret.position, _len)

    def on_cm_copy(self):
        """ copy as plain ascii/hex
        """
        start = self.selection.start
        end = self.selection.end

        if start == end:
            return

        if self.caret.mode == 'ascii':
            data = self.data[start:end]
            pyperclip.copy(self.to_ascii(data))
        else:
            data = self.data[start:end]
            data_str = "".join(['{:02x} '.format(x) for x in data])
            pyperclip.copy(data_str)

    def on_cm_copy_as(self, menu):
        """ copy as formatted
        """
        start = self.selection.start
        end = self.selection.end

        if start == end:
            return

        # get menutext
        what = menu.text()

        if what == 'C Source':
            pyperclip.copy(self.make_c_array(start, end))
        elif what == 'Python Source':
            pyperclip.copy(self.make_py_array(start, end))
        elif what == 'JS Source':
            pyperclip.copy(self.make_js_array(start, end))

    def on_cm_paste(self):
        """ paste plain ascii or hex
        """

    def on_cm_paste_from(self):
        """ paste from formated
        """

    def on_cm_fill(self):
        """ Fills len data with given byte
        """
        start = self.selection.start
        end = self.selection.end
        count = 0
        byte = 0

        if start == end:
            # ask how many bytes
            res, exp = InputDialog.input(
                self, hint='byte * count', placeholder='0x00*10')
            if res and exp:
                if not '*' in exp:
                    return

                byte, count = exp.split('*')
                try:
                    count = int(count, 10)
                    byte = int(byte, 16)
                except ValueError:
                    return
        else:
            # ask for byte
            res, exp = InputDialog.input(self, hint='byte', placeholder='0x00')
            if res and exp:
                if '*' in exp:
                    return

                try:
                    count = end - start
                    byte = int(exp, 16)
                except ValueError:
                    return

        if count <= 0 or count > len(self.data):
            return

        if start == end:
            start_loc = self.caret.position
        else:
            start_loc = start

        data_bt = bytearray(self.data)

        for i in range(start_loc, start_loc + count):
            data_bt[i] = byte

        self.data = bytes(data_bt)
        self.add_highlight(HighLight('edited', start_loc + self.base, count))
        self.dataChanged.emit(start_loc, count)
        self.viewChanged.emit()

    # ************************************************************************
    # **************************** Painting **********************************
    # ************************************************************************
    def paint_selection(self, painter):
        """ paints selection rects
        """
        if self.selection.start == self.selection.end:
            return

        pen_color = QColor(self._ctrl_colors['selection_bg'])
        brush_color = QColor(self._ctrl_colors['selection_bg'])
        brush_color.setAlpha(100)

        start_x_hex, start_y_hex = self.index_to_hexcol(self.selection.start)
        end_x_hex, end_y_hex = self.index_to_hexcol(self.selection.end)
        start_x_ascii, start_y_ascii = self.index_to_asciicol(
            self.selection.start)
        end_x_ascii, end_y_ascii = self.index_to_asciicol(self.selection.end)

        # single line selection
        if start_y_hex == end_y_hex:
            # select color if hexsel then with background or outline only
            if self.caret.mode == 'hex':
                painter.setPen(pen_color)
                painter.setBrush(brush_color)
            else:
                painter.setPen(pen_color)
                painter.setBrush(Qt.NoBrush)

            # draw selection in hexcolumn
            painter.drawRect(
                start_x_hex
                - (self._char_width / 2),  # offset by half charwidth
                start_y_hex - self._base_line - 1,  # baseline offset
                end_x_hex - start_x_hex,
                self._char_height + 1)

            # switch style
            if self.caret.mode == 'hex':
                painter.setPen(pen_color)
                painter.setBrush(Qt.NoBrush)
            else:
                painter.setPen(pen_color)
                painter.setBrush(brush_color)

            # draw selection in asciicolumn
            painter.drawRect(
                start_x_ascii,  # offset by half charwidth
                start_y_ascii - self._base_line - 1,  # baseline offset
                end_x_ascii - start_x_ascii,
                self._char_height + 1)

        elif self.selection.end - self.selection.start <= self.bytes_per_line:
            # selection over two lines but not joining draw 2 rects
            if self.caret.mode == 'hex':
                painter.setPen(pen_color)
                painter.setBrush(brush_color)
            else:
                painter.setPen(pen_color)
                painter.setBrush(Qt.NoBrush)

            # draw selection in hexcolumn
            painter.drawRect(
                start_x_hex
                - (self._char_width / 2),  # offset by half charwidth
                start_y_hex - self._base_line - 1,  # baseline offset
                ((self._hex_start + self._hex_width) - start_x_hex)
                + self._char_width,
                self._char_height + 2)
            if self.selection.end % self.bytes_per_line != 0:
                painter.drawRect(
                    self._hex_start
                    - (self._char_width / 2),  # offset by half charwidth
                    end_y_hex - self._base_line - 1,  # baseline offset
                    end_x_hex - self._hex_start,
                    self._char_height + 2)

            if self.caret.mode == 'hex':
                painter.setPen(pen_color)
                painter.setBrush(Qt.NoBrush)
            else:
                painter.setPen(pen_color)
                painter.setBrush(brush_color)

            # draw selection in hexcolumn
            painter.drawRect(
                start_x_ascii,  # offset by half charwidth
                start_y_ascii - self._base_line - 1,  # baseline offset
                ((self._ascii_start + self._ascii_width) - start_x_ascii),
                self._char_height + 2)
            if self.selection.end % self.bytes_per_line != 0:
                painter.drawRect(
                    self._ascii_start,  # offset by half charwidth
                    end_y_ascii - self._base_line - 1,  # baseline offset
                    end_x_ascii - self._ascii_start,
                    self._char_height + 2)
        else:
            # multiple lines selection
            painter.setPen(pen_color)
            painter.setBrush(brush_color)
            polygon = QPolygon()
            polygon.append(
                QPoint(start_x_hex - (self._char_width / 2),
                       start_y_hex + self._char_height - self._base_line + 1))
            polygon.append(
                QPoint(start_x_hex - (self._char_width / 2),
                       start_y_hex - self._base_line - 1))
            polygon.append(
                QPoint(
                    self._hex_start + self._hex_width + (self._char_width / 2),
                    start_y_hex - self._base_line - 1))
            polygon.append(
                QPoint(
                    self._hex_start + self._hex_width + (self._char_width / 2),
                    end_y_hex - self._base_line - 1))
            if self.selection.end % self.bytes_per_line != 0:
                polygon.append(
                    QPoint(end_x_hex - (self._char_width / 2),
                           end_y_hex - self._base_line - 1))
                polygon.append(
                    QPoint(
                        end_x_hex - (self._char_width / 2),
                        end_y_hex + self._char_height - self._base_line + 1))
                polygon.append(
                    QPoint(
                        self._hex_start - (self._char_width / 2),
                        end_y_hex + self._char_height - self._base_line + 1))
            else:
                polygon.append(
                    QPoint(end_x_hex - (self._char_width / 2),
                           end_y_hex - self._base_line - 1))
            polygon.append(
                QPoint(self._hex_start - (self._char_width / 2),
                       start_y_hex + self._char_height - self._base_line + 1))
            polygon.append(
                QPoint(start_x_hex - (self._char_width / 2),
                       start_y_hex + self._char_height - self._base_line + 1))

            if self.caret.mode == 'hex':
                painter.drawPolygon(polygon)
            else:
                painter.drawPolyline(polygon)

            polygon = QPolygon()
            # left linebottom -> left linetop
            polygon.append(
                QPoint(
                    start_x_ascii,
                    start_y_ascii + self._char_height - self._base_line + 1))
            # top left -> right top
            polygon.append(
                QPoint(start_x_ascii, start_y_ascii - self._base_line - 1))
            # right top -> right bottom
            polygon.append(
                QPoint(self._ascii_start + self._ascii_width,
                       start_y_ascii - self._base_line - 1))
            polygon.append(
                QPoint(self._ascii_start + self._ascii_width,
                       end_y_ascii - self._base_line - 1))

            if self.selection.end % self.bytes_per_line != 0:  # caret already next linestart
                polygon.append(
                    QPoint(end_x_ascii, end_y_ascii - self._base_line - 1))
                polygon.append(
                    QPoint(
                        end_x_ascii,
                        end_y_ascii + self._char_height - self._base_line + 1))
                polygon.append(
                    QPoint(
                        self._ascii_start,
                        end_y_ascii + self._char_height - self._base_line + 1))
            else:
                polygon.append(
                    QPoint(end_x_ascii, end_y_ascii - self._base_line - 1))

            # bottom left -> linetop
            polygon.append(
                QPoint(
                    self._ascii_start,
                    start_y_ascii + self._char_height - self._base_line + 1))
            # back to begin
            polygon.append(
                QPoint(
                    start_x_ascii,
                    start_y_ascii + self._char_height - self._base_line + 1))

            if self.caret.mode == 'hex':
                painter.drawPolyline(polygon)
            else:
                painter.drawPolygon(polygon)

    def paint_error(self, painter):
        """ paint error popup
        """
        brdr_col = QColor('#444')
        back_col = QColor('#222')
        painter.setPen(Qt.red)
        back_rect = self.viewport().rect()
        back_rect.setWidth(back_rect.width() / 4)
        back_rect.setHeight(back_rect.height() / 4)
        screen_x = self.viewport().width() / 2
        screen_x -= back_rect.width() / 2
        screen_y = self.viewport().height() / 2
        screen_y -= back_rect.height() / 2
        painter.fillRect(0, 0,
                         self.viewport().width(),
                         self.viewport().height(), QColor('#99000000'))
        painter.fillRect(screen_x - 1, screen_y - 1,
                         back_rect.width() + 2,
                         back_rect.height() + 2, brdr_col)
        painter.fillRect(screen_x, screen_y, back_rect.width(),
                         back_rect.height(), back_col)
        qtext_align = QTextOption(Qt.AlignVCenter | Qt.AlignHCenter)
        text_rect = QRectF(screen_x + 10, screen_y + 10,
                           back_rect.width() - 20,
                           back_rect.height() - 20)
        painter.drawText(text_rect, self._error_message, option=qtext_align)

    def paint_control(self, painter):
        """ paint main control
        """
        qtext_align = QTextOption(Qt.AlignVCenter | Qt.AlignHCenter)
        painter.setPen(self._ctrl_colors['foreground'])

        # header
        painter.fillRect(0, 0, self.width(), self._header_height,
                         self._ctrl_colors['header_bg'])

        # header texts
        if self._hex_style == 'upper':
            hex_style = 'X'
        else:
            hex_style = 'x'

        bounds = QRectF(self._offset_start, 0, self._offset_width,
                        self._header_height)
        painter.drawText(bounds, "OFFSET(%s)" % hex_style, option=qtext_align)

        drawing_pos_x = self._hex_start

        painter.setPen(self._ctrl_colors['foreground'])
        for i in range(self.bytes_per_line):
            if self._dual_color_bytes and not i % 2:
                painter.setPen(self._ctrl_colors['byte_col_1'])
            elif self._dual_color_bytes and i % 2:
                painter.setPen(self._ctrl_colors['byte_col_2'])
            else:
                painter.setPen(self._ctrl_colors['foreground'])

            bounds = QRectF(drawing_pos_x, 0, (2 * self._char_width),
                            self._header_height)
            if self._hex_style == 'upper':
                painter.drawText(
                    bounds, '{0:02X}'.format(i), option=qtext_align)
            else:
                painter.drawText(
                    bounds, '{0:02x}'.format(i), option=qtext_align)

            drawing_pos_x += (3 * self._char_width)

        # draw separator lines
        if self._draw_sep_lines:
            line_pos_x = self._hex_start - self._line_width - self._hor_spacing
            painter.fillRect(line_pos_x, 0, self._line_width, self.height(),
                             self._ctrl_colors['divider'])
            line_pos_x = self._ascii_start - self._line_width - self._hor_spacing
            painter.fillRect(line_pos_x, 0, self._line_width, self.height(),
                             self._ctrl_colors['divider'])

        painter.setPen(self._ctrl_colors['foreground'])
        bounds = QRectF(self._ascii_start, 0, self._ascii_width,
                        self._header_height)
        painter.drawText(
            bounds,
            "ASCII",
            option=QTextOption(Qt.AlignVCenter | Qt.AlignHCenter))

    def do_paint(self, event):
        """ main paint
        """
        if not self.isVisible():
            return

        old_offset_start = self._offset_start
        old_hex_start = self._hex_start
        old_ascii_start = self._ascii_start
        scroll_x = self.horizontalScrollBar().value()
        self._offset_start -= scroll_x
        self._hex_start -= scroll_x
        self._ascii_start -= scroll_x

        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.HighQualityAntialiasing)

        # fill background
        painter.fillRect(self.viewport().rect(),
                         self._ctrl_colors['background'])

        # no data stop paint
        if self.data is None:
            return

        # hover current line
        if self._hover_lines and self._hovered_line != -1:
            screen_x, screen_y = self.data_to_pixel(0, self._hovered_line)
            screen_y -= self._base_line
            painter.fillRect(0, screen_y - 1,
                             self.viewport().width(), self._char_height + 2,
                             self._ctrl_colors['linecol'])

        # update carets
        if not self._error_message:
            if event.rect() == self.caret_to_hexcol(self.caret):
                if self._blink:
                    painter.fillRect(
                        self.caret_to_hexcol(self.caret), QColor('#ef5350'))
                self.viewport().update(self.caret_to_asciicol(self.caret))
                return

            if event.rect() == self.caret_to_asciicol(self.caret):
                if self._blink:
                    painter.fillRect(
                        self.caret_to_asciicol(self.caret), QColor('#ef5350'))
                return

        self.pos = self.verticalScrollBar().value() * self.bytes_per_line

        # set pos_y
        drawing_pos_y = self._header_height + self._char_height + self._ver_spacing

        # draw carets
        if self._blink:
            if self.caret_to_hexcol(self.caret).top() < self.height():
                if self.caret_to_hexcol(self.caret).bottom() > 0:
                    painter.fillRect(
                        self.caret_to_hexcol(self.caret), QColor('#ef5350'))
                    painter.fillRect(
                        self.caret_to_asciicol(self.caret), QColor('#ef5350'))

        # paint selection
        self.paint_selection(painter)

        # paint visisble lines
        for i, line in enumerate(self.get_lines(self.pos)):

            if i > self.visible_lines() - 1:
                break

            has_highlight = False

            # get data
            (address, length, ascii_) = line
            data = self.data[address:address + length]

            # fixup offset
            address += self.base

            # paint address
            if i == self._hovered_line:
                painter.setPen(QColor('#ef5350'))
            else:
                painter.setPen(self._ctrl_colors['foreground'])

            addr = '{0:08X}'
            if self._is_64bit_addr:
                if self._hex_style == 'upper':
                    addr = "{0:016X}"
                else:
                    addr = "{0:016x}"
            else:
                if self._hex_style == 'upper':
                    addr = "{0:08X}"
                else:
                    addr = "{0:08x}"

            # paint addr
            rect = QRectF(self._offset_start, drawing_pos_y - self._base_line,
                          self._offset_width, self._char_height)
            painter.drawText(rect, addr.format(address),
                             QTextOption(Qt.AlignHCenter | Qt.AlignBaseline))

            drawing_pos_x = self._hex_start
            is_in_selection = False

            # hex data
            for j, byte in enumerate(data):
                if self._dual_color_bytes and not j % 2:
                    if i == self._hovered_line:
                        painter.setPen(self._ctrl_colors['selection_fg'])
                    else:
                        painter.setPen(self._ctrl_colors['byte_col_1'])
                elif self._dual_color_bytes and j % 2:
                    if i == self._hovered_line:
                        painter.setPen(self._ctrl_colors['selection_fg'])
                    else:
                        painter.setPen(self._ctrl_colors['byte_col_2'])
                else:
                    painter.setPen(self._ctrl_colors['foreground'])

                if self.selection.start <= (
                        address + j) - self.base < self.selection.end:
                    painter.setPen(self._ctrl_colors['selection_fg'])
                    is_in_selection = True

                # set highlightcolor if needed
                highlight = self.is_highlighted(address + j)
                if highlight:
                    has_highlight = True
                    painter.setPen(self._highlight_colors[highlight])

                # paint hex
                if self._hex_style == 'upper':
                    painter.drawText(drawing_pos_x, drawing_pos_y,
                                     "{:02X} ".format(byte))
                else:
                    painter.drawText(drawing_pos_x, drawing_pos_y,
                                     "{:02x} ".format(byte))
                drawing_pos_x += (3 * self._char_width)

            # restore color
            if i == self._hovered_line:
                painter.setPen(self._ctrl_colors['selection_fg'])
            else:
                painter.setPen(self._ctrl_colors['foreground'])

            # draw whole ascii if no highlight
            if not has_highlight and not is_in_selection:
                painter.drawText(self._ascii_start, drawing_pos_y, ascii_)
            else:
                for a, c in enumerate(ascii_):
                    highlight = self.is_highlighted(address + a)
                    if highlight:
                        painter.setPen(self._highlight_colors[highlight])
                    else:
                        if i == self._hovered_line:
                            painter.setPen(self._ctrl_colors['selection_fg'])
                        else:
                            painter.setPen(self._ctrl_colors['foreground'])

                        if self.selection.start <= (
                                address + a) - self.base < self.selection.end:
                            painter.setPen(self._ctrl_colors['selection_fg'])

                    painter.drawText(
                        self._ascii_start + (a * self._char_width),
                        drawing_pos_y, c)

            # new y
            drawing_pos_y += self._char_height + self._ver_spacing
            # reset x
            drawing_pos_x = self._hex_start

        # paint ctrl stuff - header etc
        self.paint_control(painter)

        # paint errorstr
        if self._error_message:
            self.paint_error(painter)

        self._offset_start = old_offset_start
        self._hex_start = old_hex_start
        self._ascii_start = old_ascii_start

    def on_context_setup(self):
        if '64' in self.app.dwarf.arch:
            self.is_64bit_address = True
        else:
            self.is_64bit_address = False

        self._addr_width_changed()

    def on_script_destroyed(self):
        self.data = None

    def clear_panel(self):
        self.data = None
