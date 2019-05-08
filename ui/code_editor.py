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
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, \
    QFileDialog, QSpinBox, QLabel, QWidget, QPlainTextEdit, QCompleter
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QFontDatabase, QPainter, QTextCursor
from PyQt5.QtCore import QFile, QRegExp, Qt, QRegularExpression, QRect, QSize, QStringListModel, pyqtSignal

from lib.utils import get_os_monospace_font
from lib.prefs import Prefs
from ui.dialog_scripts import ScriptsDialog


class DwarfCompleter(QCompleter):
    insertText = pyqtSignal(str)

    def __init__(self, myKeywords=None, parent=None):
        myKeywords = [
            'api.findExport(', 'api.addWatcher(', 'console', 'console.log(',
            'log', 'addWatcher', 'deleteHook', 'enumerateJavaClasses',
            'enumerateJavaMethods', 'findExport', 'getAddressTs',
            'hookAllJavaMethods', 'hookJava', 'hookNative'
            'hookOnLoad', 'javaBacktrace', 'isAddressWatched',
            'nativeBacktrace', 'release', 'removeWatcher', 'restart',
            'setData',
            # trace
            'startNativeTracer',
            'stopNativeTracer',
            # emu
            'emulator',
            'emulator.clean()',
            'emulator.start(',
            'emulator.step()',
            'emulator.stop()',
        ]
        QCompleter.__init__(self, myKeywords, parent)
        self.setCompletionMode(QCompleter.PopupCompletion)
        self.highlighted.connect(self.setHighlighted)

    def setHighlighted(self, text):
        self.lastSelected = text

    def getSelected(self):
        return self.lastSelected


class JsHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(JsHighlighter, self).__init__(parent)

        self.keyword_color = QColor('#C678DD')
        self.comment_color = QColor('#5C6370')
        self.function_color = QColor('#61AFEF')
        self.string_color = QColor('#98C379')
        self.number_color = QColor('#e06c75')
        self.constant_color = QColor('#D19A66')

        self._keywords = [
            "break", "case", "catch", "class", "const", "continue", "debugger",
            "default", "delete", "do", "else", "export", "extends", "false", "finally",
            "for", "function", "if", "import", "in", "instanceof", "new", "null",
            "return", "super", "switch", "this", "throw", "true", "try", "typeof",
            "var", "void", "while", "with", "yield"
        ]

        self._known_m = [
            "Memory", "Process", "MemoryWatcher", "Thread", "Object", "Function", "Interceptor", "Java",
            "JSON", "console"
        ]

        self._known = [
            'log', 'addWatcher', 'deleteHook', 'enumerateJavaClasses',
            'enumerateJavaMethods', 'findExport', 'getAddressTs',
            'hookAllJavaMethods', 'hookJava', 'hookNative'
            'hookOnLoad', 'javaBacktrace', 'isAddressWatched',
            'nativeBacktrace', 'release', 'removeWatcher', 'restart',
            'setData', 'startNativeTracer', 'stopNativeTracer',
            "prototype",
            "create",
            "defineProperty",
            "defineProperties",
            "getOwnPropertyDescriptor",
            "keys",
            "getOwnPropertyNames",
            "constructor",
            "__parent__",
            "__proto__",
            "__defineGetter__",
            "__defineSetter__",
            "eval",
            "hasOwnProperty",
            "isPrototypeOf",
            "__lookupGetter__",
            "__lookupSetter__",
            "__noSuchMethod__",
            "propertyIsEnumerable",
            "toSource",
            "toLocaleString",
            "toString",
            "unwatch",
            "valueOf",
            "watch",
            "arguments",
            "arity",
            "caller",
            "constructor",
            "length",
            "name",
            "apply",
            "bind",
            "call",
            "String",
            "fromCharCode",
            "length",
            "charAt",
            "charCodeAt",
            "concat",
            "indexOf",
            "lastIndexOf",
            "localCompare",
            "match",
            "quote",
            "replace",
            "search",
            "slice",
            "split",
            "substr",
            "substring",
            "toLocaleLowerCase",
            "toLocaleUpperCase",
            "toLowerCase",
            "toUpperCase",
            "trim",
            "trimLeft",
            "trimRight",
            "Array",
            "isArray",
            "index",
            "input",
            "pop",
            "push",
            "reverse",
            "shift",
            "sort",
            "splice",
            "unshift",
            "concat",
            "join",
            "filter",
            "forEach",
            "every",
            "map",
            "some",
            "reduce",
            "reduceRight",
            "RegExp",
            "global",
            "ignoreCase",
            "lastIndex",
            "multiline",
            "source",
            "exec",
            "test",
            "parse",
            "stringify",
            "decodeURI",
            "decodeURIComponent",
            "encodeURI",
            "encodeURIComponent",
            "eval",
            "isFinite",
            "isNaN",
            "parseFloat",
            "parseInt",
            "Infinity",
            "NaN",
            "undefined",
            "Math",
            "E",
            "LN2",
            "LN10",
            "LOG2E",
            "LOG10E",
            "PI",
            "SQRT1_2",
            "SQRT2",
            "abs",
            "acos",
            "asin",
            "atan",
            "atan2",
            "ceil",
            "cos",
            "exp",
            "floor",
            "log",
            "max",
            "min",
            "pow",
            "random",
            "round",
            "sin",
            "sqrt",
            "tan",
            "document",
            "window",
            "navigator",
            "userAgent",
        ]

        self.highlightingRules = []

        classFormat = QTextCharFormat()
        classFormat.setFontWeight(QFont.Bold)
        classFormat.setForeground(self.constant_color)
        self.highlightingRules.append((QRegExp("\\bnew [A-Za-z]+\\b"),
                                       classFormat))

        functionFormat = QTextCharFormat()
        functionFormat.setForeground(self.function_color)
        self.highlightingRules.append(
            (QRegExp("(?!function)\\b[A-Za-z0-9_]+(?=\\()"), functionFormat))

    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            expression = QRegExp(pattern)
            expression.setMinimal(True)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)

        blockState = self.previousBlockState()
        bracketLevel = blockState >> 4
        state = blockState & 15

        if blockState < 0:
            bracketLevel = 0
            state = 0

        start = 0
        i = 0
        while i < len(text):
            cur_ch = ''
            next_ch = ''
            if i < len(text):
                cur_ch = text[i]
            if i < len(text) - 1:
                next_ch = text[i + 1]

            if state == 0:  # Start
                start = i

                if cur_ch.isspace():
                    i += 1
                elif cur_ch.isdigit():
                    i += 1
                    state = 1
                elif cur_ch.isalpha() or cur_ch == '_':
                    i += 1
                    state = 2
                elif cur_ch == '\'' or cur_ch == '\"':
                    i += 1
                    state = 3
                elif cur_ch == '/' and next_ch == '*':
                    i += 2
                    state = 4
                elif cur_ch == '/' and next_ch == '/':
                    i = len(text)
                    self.setFormat(start, len(text), self.comment_color)
                elif cur_ch == '/' and next_ch != '*':
                    i += 1
                    state = 5
                else:
                    if cur_ch not in '(){}[],.;':
                        self.setFormat(start, 1, QColor('#099A00'))
                    if cur_ch in '{}':
                        #bracketPositions += i
                        if cur_ch == '{':
                            bracketLevel += 1
                        else:
                            bracketLevel -= 1
                    i += 1
                    state = 0

            elif state == 1:  # Number
                if cur_ch.isspace() or not cur_ch.isdigit():
                    self.setFormat(start, i - start, self.number_color)
                    state = 0
                else:
                    i += 1

            elif state == 2:
                if cur_ch.isspace() or not (cur_ch.isdigit() or cur_ch.isalpha() or cur_ch in '_-'):
                    token = text[start:i].strip()
                    if token in self._keywords:
                        self.setFormat(start, i - start, self.keyword_color)
                    elif token in self._known:
                        self.setFormat(start, i - start, self.function_color)
                    elif token in self._known_m:
                        self.setFormat(start, i - start, self.constant_color)
                    state = 0
                else:
                    i += 1

            elif state == 3:
                if cur_ch == text[start]:
                    prev_ch = ''
                    if i > 0:
                        prev_ch = text[i - 1]

                    if prev_ch != '\\':
                        i += 1
                        self.setFormat(start, i - start, self.string_color)
                        state = 0
                    else:
                        i += 1
                else:
                    i += 1
            elif state == 4:
                if cur_ch == '*' and next_ch == '/':
                    i += 2
                    self.setFormat(start, i - start, self.comment_color)
                    state = 0
                else:
                    i += 1

            elif state == 5:
                if cur_ch == '/':
                    prev_ch = ''
                    if i > 0:
                        prev_ch = text[i - 1]

                    if prev_ch != '\\':
                        i += 1
                        self.setFormat(start, i - start, self.string_color)
                        state = 0
                    else:
                        i += 1
                else:
                    i += 1
            else:
                state = 0

        if state == 4:
            self.setFormat(start, len(text), self.comment_color)
        else:
            state = 0

        blockState = (state & 15) | (bracketLevel << 4)
        self.setCurrentBlockState(blockState)


class JsCodeEditLineNums(QWidget):
    # todo: allow styling
    def __init__(self, parent=None):
        super(JsCodeEditLineNums, self).__init__(parent)
        self.editor = parent

    def sizeHint(self, event):
        return QSize(self.editor.calculated_linenum_width(), 0)

    def paintEvent(self, event):
        self.editor.draw_line_numbers(event)


class JsCodeEditor(QPlainTextEdit):
    # todo: linehighlight
    def __init__(self, parent=None):
        super(JsCodeEditor, self).__init__(parent)

        self.setFont(get_os_monospace_font())

        self._show_linenums = False

        if self._show_linenums:
            self.ui_line_numbers = JsCodeEditLineNums(self)
            self.blockCountChanged.connect(self.update_linenum_width)
            self.updateRequest.connect(self.update_line_numbers)
            self.update_linenum_width(0)

        self.setAutoFillBackground(True)
        # default distance is 80
        self.setTabStopDistance(self.fontMetrics().width('9999'))

        self.highlighter = JsHighlighter(self.document())

        # code completion
        self.completer = DwarfCompleter()
        self.completer.setWidget(self)
        self.completer.setCompletionMode(QCompleter.PopupCompletion)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.completer.insertText.connect(self.insertCompletion)

    @property
    def line_numbers(self):
        return self._show_linenums

    @line_numbers.setter
    def line_numbers(self, value):
        self._show_linenums = value
        self.ui_line_numbers = JsCodeEditLineNums(self)
        self.blockCountChanged.connect(self.update_linenum_width)
        self.updateRequest.connect(self.update_line_numbers)
        self.update_linenum_width(0)

    def update_linenum_width(self, count):
        self.setViewportMargins(self.calculated_linenum_width() + 10, 0, 0, 0)

    def update_line_numbers(self, rect, y):
        if y:
            self.ui_line_numbers.scroll(0, y)
        else:
            self.ui_line_numbers.update(0, rect.y(),
                                        self.ui_line_numbers.width(),
                                        rect.height())

        if rect.contains(self.viewport().rect()):
            self.update_linenum_width(0)

    def calculated_linenum_width(self):
        _char_width = self.fontMetrics().width("9")
        digits = 0
        m = max(1, self.blockCount())
        while m >= 10:
            m /= 10
            digits += 1

        # min_width + width * digits
        _width = 10 + _char_width * digits
        return _width + 10

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._show_linenums:
            bounds = self.contentsRect()
            new_bounds = QRect(bounds.left(), bounds.top(),
                               self.calculated_linenum_width(),
                               bounds.height())
            self.ui_line_numbers.setGeometry(new_bounds)

    def draw_line_numbers(self, event):
        painter = QPainter(self.ui_line_numbers)
        # background
        painter.fillRect(event.rect(), Qt.transparent)

        # linenums
        current_block = self.firstVisibleBlock()
        block_num = current_block.blockNumber()

        top = self.blockBoundingGeometry(current_block).translated(
            self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(current_block).height()

        while current_block.isValid() and (top <= event.rect().bottom()):
            if current_block.isVisible() and (bottom >= event.rect().top()):
                s = ("{0}".format(block_num + 1))
                painter.setPen(QColor('#636d83'))
                painter.setFont(self.font())
                painter.drawText(0, top,
                                 self.calculated_linenum_width() - 5,
                                 self.fontMetrics().height(),
                                 Qt.AlignRight | Qt.AlignVCenter, s)

            current_block = current_block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(current_block).height()
            block_num += 1

    def focusInEvent(self, event):
        if self.completer:
            self.completer.setWidget(self)
        super().focusInEvent(event)

    def keyPressEvent(self, event):

        tc = self.textCursor()
        if event.key() == Qt.Key_Enter or event.key(
        ) == Qt.Key_Return or event.key() == Qt.Key_Tab:
            if self.completer.popup().isVisible():
                self.completer.insertText.emit(self.completer.getSelected())
                self.completer.setCompletionMode(QCompleter.PopupCompletion)
                event.ignore()
                return

        super().keyPressEvent(event)

        tc.select(QTextCursor.WordUnderCursor)
        cr = self.cursorRect()

        if len(tc.selectedText()) > 0:
            self.completer.setCompletionPrefix(tc.selectedText())
            popup = self.completer.popup()
            popup.setCurrentIndex(self.completer.completionModel().index(0, 0))

            cr.setWidth(
                self.completer.popup().sizeHintForColumn(0) +
                self.completer.popup().verticalScrollBar().sizeHint().width())
            self.completer.complete(cr)
        else:
            self.completer.popup().hide()

        return
        if self.completer and self.completer.popup() and self.completer.popup(
        ).isVisible():
            if event.key() in (Qt.Key_Enter, Qt.Key_Return, Qt.Key_Escape,
                               Qt.Key_Tab, Qt.Key_Backtab):
                event.ignore()
                return
            # return super().keyPressEvent(event)

        isShortcut = (event.modifiers() == Qt.ControlModifier
                      and event.key() == Qt.Key_Space)
        if (not self.completer or not isShortcut):
            super().keyPressEvent(event)

        ctrlOrShift = event.modifiers() in (Qt.ControlModifier,
                                            Qt.ShiftModifier)
        if ctrlOrShift and event.text() == '':
            return

        eow = "~!@#$%^&*+{}|:\"<>?,./;'[]\\-="  # end of word

        hasModifier = ((event.modifiers() != Qt.NoModifier)
                       and not ctrlOrShift)

        completionPrefix = self.textUnderCursor()

        if not isShortcut:
            if self.completer.popup():
                self.completer.popup().hide()
            return

        self.completer.setCompletionPrefix(completionPrefix)
        popup = self.completer.popup()
        popup.setCurrentIndex(self.completer.completionModel().index(0, 0))
        cr = self.cursorRect()
        cr.setWidth(self.completer.popup().sizeHintForColumn(
            0) + self.completer.popup().verticalScrollBar().sizeHint().width())
        self.completer.complete(cr)

    def insertCompletion(self, completion):
        tc = self.textCursor()
        extra = (len(completion) - len(self.completer.completionPrefix()))
        tc.movePosition(QTextCursor.Left)
        tc.movePosition(QTextCursor.EndOfWord)
        tc.insertText(completion[-extra:])
        self.setTextCursor(tc)
        self.completer.popup().hide()

    def textUnderCursor(self):
        tc = self.textCursor()
        tc.select(QTextCursor.WordUnderCursor)
        return tc.selectedText()
