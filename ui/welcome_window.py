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
import random
import json

from PyQt5.QtCore import Qt, QSize, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QPixmap, QIcon, QStandardItemModel, QStandardItem, QFontMetrics
from PyQt5.QtWidgets import (QWidget, QDialog, QLabel, QVBoxLayout,
                             QHBoxLayout, QPushButton, QSpacerItem,
                             QSizePolicy, QStyle, qApp, QHeaderView, QMenu)

from lib import utils, prefs
from lib.git import Git
from ui.widgets.list_view import DwarfListView


class DwarfCommitsThread(QThread):
    """ Commits Thread
    signals:
            on_status_text(str)
            on_add_commit(str, bool) - adds item to list (bool == use white color)
            on_update_available()
            on_finished(str)
    """

    on_status_text = pyqtSignal(str)
    on_update_available = pyqtSignal()
    on_add_commit = pyqtSignal(str, bool)
    on_finished = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        self.on_status_text.emit('fetching commit list...')

        try:
            utils.do_shell_command('git --version')
        except IOError as io_error:
            if io_error.errno == 2:
                # git command not available
                self.on_status_text.emit(
                    'error: git not available on your system')
                return
        _git = Git()
        data = _git.get_dwarf_commits()
        if data is None:
            self.on_status_text.emit('Failed to fetch commit list. Try later.')
            return

        most_recent_remote_commit = ''
        most_recent_local_commit = utils.do_shell_command(
            'git log -1 master --pretty=format:%H')
        most_recent_date = ''
        for commit in data:
            if most_recent_remote_commit == '':
                most_recent_remote_commit = commit['sha']
                if most_recent_remote_commit != most_recent_local_commit:
                    self.on_update_available.emit()

            commit = commit['commit']
            date = commit['committer']['date'].split('T')
            if most_recent_date != date[0]:
                if most_recent_date != '':
                    self.on_add_commit.emit('', True)
                self.on_add_commit.emit(date[0], True)
                most_recent_date = date[0]

            s = ('{0} - {1} ({2})'.format(date[1][:-1], commit['message'],
                                          commit['author']['name']))
            self.on_add_commit.emit(s, False)

        if most_recent_remote_commit != most_recent_local_commit:
            self.on_finished.emit(
                'There is an newer Version available... You can use the UpdateButton in Menu'
            )
        else:
            # keep: it clears status text
            self.on_finished.emit('')


class DwarfUpdateThread(QThread):
    """ Dwarf update Thread
        signals:
            on_status_text(str)
            on_finished(str)
    """

    on_status_text = pyqtSignal(str)
    on_finished = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        self.on_status_text.emit('updating dwarf...')

        try:
            utils.do_shell_command('git --version')
        except IOError as io_error:
            if io_error.errno == 2:
                # git command not available
                self.on_status_text.emit(
                    'error while updating: git not available on your system')
                self.on_finished.emit(
                    'error while updating: git not available on your system')
                return

        utils.do_shell_command(
            'git fetch -q https://github.com/iGio90/Dwarf.git')
        utils.do_shell_command('git checkout -f -q master')
        utils.do_shell_command('git reset --hard FETCH_HEAD')
        sha = utils.do_shell_command('git log -1 master --pretty=format:%H')

        s = ('Dwarf updated to commit := {0} - Please restart...'.format(sha))
        self.on_status_text.emit(s)
        self.on_finished.emit(sha)


class UpdateBar(QWidget):
    onUpdateNowClicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setAutoFillBackground(True)
        self.setStyleSheet(
            'background-color: crimson; color: white; font-weight: bold; margin: 0; padding: 10px;'
        )
        self.setup()

    def setup(self):
        """ Setup ui
        """
        h_box = QHBoxLayout()
        h_box.setContentsMargins(0, 0, 0, 0)
        update_label = QLabel(
            'A newer Version of Dwarf is available. Checkout <a style="color:white;" '
            'href="https://github.com/iGio90/Dwarf">Dwarf on GitHub</a> for more informations'
        )
        update_label.setOpenExternalLinks(True)
        update_label.setTextFormat(Qt.RichText)
        update_label.setTextInteractionFlags(Qt.TextBrowserInteraction)

        self.update_button = QPushButton('Update now!', update_label)
        self.update_button.setStyleSheet('padding: 0; border-color: white;')
        self.update_button.setGeometry(
            self.parent().width() - 10 - update_label.width() * .2, 5,
            update_label.width() * .2, 25)
        self.update_button.clicked.connect(self.update_now_clicked)
        h_box.addWidget(update_label)
        self.setLayout(h_box)

    def update_now_clicked(self):
        """ Update Button clicked
        """
        self.onUpdateNowClicked.emit()

    def showEvent(self, QShowEvent):
        h_center = self.update_button.parent().rect().center() - self.update_button.rect().center()
        self.update_button.move(self.update_button.parent().width() - self.update_button.width() - 10, h_center.y())
        return super().showEvent(QShowEvent)


class WelcomeDialog(QDialog):
    onSessionSelected = pyqtSignal(str, name='onSessionSelected')
    onSessionRestore = pyqtSignal(dict, name='onSessionRestore')
    onUpdateComplete = pyqtSignal(name='onUpdateComplete')
    onIsNewerVersion = pyqtSignal(name='onIsNewerVersion')

    def __init__(self, parent=None):
        super(WelcomeDialog, self).__init__(parent=parent)

        self._prefs = parent.prefs

        self._sub_titles = [
            ['duck', 'dumb', 'doctor', 'dutch', 'dark', 'dirty', 'debugging'],
            ['warriors', 'wardrobes', 'waffles', 'wishes', 'worcestershire'],
            ['are', 'aren\'t', 'ain\'t', 'appears to be'],
            ['rich', 'real', 'riffle', 'retarded', 'rock'],
            [
                'as fuck', 'fancy', 'fucked', 'front-ended', 'falafel',
                'french fries'
            ],
        ]

        self._update_thread = None

        self._recent_list_model = QStandardItemModel(0, 6)
        self._recent_list_model.setHeaderData(0, Qt.Horizontal, 'Path')
        self._recent_list_model.setHeaderData(1, Qt.Horizontal, 'Session')
        self._recent_list_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                              Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(2, Qt.Horizontal, 'Breakpoints')
        self._recent_list_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                              Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(3, Qt.Horizontal, 'Watchers')
        self._recent_list_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                              Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(4, Qt.Horizontal, 'OnLoads')
        self._recent_list_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                              Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(5, Qt.Horizontal, 'Bookmarks')
        self._recent_list_model.setHeaderData(5, Qt.Horizontal, Qt.AlignCenter,
                                              Qt.TextAlignmentRole)
        #self._recent_list_model.setHeaderData(6, Qt.Horizontal, 'Custom script')
        #self._recent_list_model.setHeaderData(6, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)

        self._recent_list = DwarfListView(self)
        self._recent_list.setModel(self._recent_list_model)

        self._recent_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents | QHeaderView.Interactive)
        self._recent_list.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(4, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(5, QHeaderView.Stretch)
        #self._recent_list.header().setSectionResizeMode(6, QHeaderView.Stretch)

        self._recent_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._recent_list.customContextMenuRequested.connect(
            self._on_recent_sessions_context_menu)
        self._recent_list.doubleClicked.connect(
            self._on_recent_session_double_click)

        # setup size and remove/disable titlebuttons
        self.desktop_geom = qApp.desktop().availableGeometry()
        self.setFixedSize(self.desktop_geom.width() * .45,
                          self.desktop_geom.height() * .4)
        self.setGeometry(
            QStyle.alignedRect(Qt.LeftToRight, Qt.AlignCenter, self.size(),
                               qApp.desktop().availableGeometry()))
        self.setSizeGripEnabled(False)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)
        self.setModal(True)

        # setup ui elements
        self.setup_ui()

        random.seed(a=None, version=2)

        self.update_commits_thread = DwarfCommitsThread(parent)
        self.update_commits_thread.on_update_available.connect(
            self._on_dwarf_isupdate)
        self.update_commits_thread.start()
        # center
        self.setGeometry(
            QStyle.alignedRect(Qt.LeftToRight, Qt.AlignCenter, self.size(),
                               qApp.desktop().availableGeometry()))

    def setup_ui(self):
        """ Setup Ui
        """
        main_wrap = QVBoxLayout()
        main_wrap.setContentsMargins(0, 0, 0, 0)

        # updatebar on top
        self.update_bar = UpdateBar(self)
        self.update_bar.onUpdateNowClicked.connect(self._update_dwarf)
        self.update_bar.setVisible(False)
        main_wrap.addWidget(self.update_bar)

        # main content
        h_box = QHBoxLayout()
        h_box.setContentsMargins(15, 15, 15, 15)
        wrapper = QVBoxLayout()
        head = QHBoxLayout()
        head.setContentsMargins(50, 10, 0, 10)
        # dwarf icon
        icon = QLabel()
        icon.setPixmap(QPixmap(utils.resource_path('assets/dwarf.svg')))
        icon.setAlignment(Qt.AlignCenter)
        icon.setMinimumSize(QSize(125, 125))
        icon.setMaximumSize(QSize(125, 125))
        head.addWidget(icon)

        # main title
        v_box = QVBoxLayout()
        title = QLabel('Dwarf')
        title.setContentsMargins(0, 0, 0, 0)
        title.setFont(QFont('Anton', 100, QFont.Bold))
        title.setMaximumHeight(125)
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        title.setAlignment(Qt.AlignCenter)
        head.addWidget(title)

        sub_title_text = (
            self._pick_random_word(0) + ' ' + self._pick_random_word(1) + ' ' +
            self._pick_random_word(2) + ' ' + self._pick_random_word(3) + ' ' +
            self._pick_random_word(4))
        sub_title_text = sub_title_text[:1].upper() + sub_title_text[1:]
        self._sub_title = QLabel(sub_title_text)
        self._sub_title.setFont(QFont('OpenSans', 16, QFont.Bold))
        font_metric = QFontMetrics(self._sub_title.font())
        self._char_width = font_metric.widthChar('#')
        self._sub_title.setAlignment(Qt.AlignCenter)
        self._sub_title.setContentsMargins(175, 0, 0, 20)
        self._sub_title.setSizePolicy(QSizePolicy.Expanding,
                                      QSizePolicy.Minimum)
        v_box.addLayout(head)
        v_box.addWidget(self._sub_title)

        wrapper.addLayout(v_box)

        recent = QLabel('Last saved Sessions')
        font = recent.font()
        font.setPointSize(11)
        font.setBold(True)
        #font.setPointSize(10)
        recent.setFont(font)
        wrapper.addWidget(recent)
        wrapper.addWidget(self._recent_list)
        h_box.addLayout(wrapper, stretch=False)
        buttonSpacer = QSpacerItem(15, 100, QSizePolicy.Fixed,
                                   QSizePolicy.Minimum)
        h_box.addItem(buttonSpacer)
        wrapper = QVBoxLayout()

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/android.svg')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Android Session')
        btn.clicked.connect(self._on_android_button)
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/apple.svg')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New iOS Session')
        btn.clicked.connect(self._on_ios_button)
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/local.svg')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Local Session')
        btn.clicked.connect(self._on_local_button)
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/remote.svg')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Remote Session')
        btn.clicked.connect(self._on_remote_button)
        wrapper.addWidget(btn)

        session_history = self._prefs.get(prefs.RECENT_SESSIONS, default=[])
        invalid_session_files = []
        for recent_session_file in session_history:
            if os.path.exists(recent_session_file):
                with open(recent_session_file, 'r') as f:
                    exported_session = json.load(f)
                hooks = '0'
                watchers = '0'
                on_loads = 0
                bookmarks = '0'
                #have_user_script = False
                if 'hooks' in exported_session and exported_session[
                        'hooks'] is not None:
                    hooks = str(len(exported_session['hooks']))
                if 'watchers' in exported_session and exported_session[
                        'watchers'] is not None:
                    watchers = str(len(exported_session['watchers']))
                if 'nativeOnLoads' in exported_session and exported_session[
                        'nativeOnLoads'] is not None:
                    on_loads += len(exported_session['nativeOnLoads'])
                if 'javaOnLoads' in exported_session and exported_session[
                        'javaOnLoads'] is not None:
                    on_loads += len(exported_session['javaOnLoads'])
                if 'bookmarks' in exported_session and exported_session[
                        'bookmarks'] is not None:
                    bookmarks = str(len(exported_session['bookmarks']))
                if 'user_script' in exported_session and exported_session[
                        'user_script']:
                    have_user_script = exported_session['user_script'] != ''

                #user_script_item = QStandardItem()
                #if have_user_script:
                #user_script_item.setIcon(self._dot_icon)

                on_loads = str(on_loads)

                recent_session_file_item = QStandardItem(recent_session_file)
                recent_session_file_item.setData(exported_session,
                                                 Qt.UserRole + 2)

                item_1 = QStandardItem(exported_session['session'])
                item_1.setTextAlignment(Qt.AlignCenter)
                item_2 = QStandardItem(hooks)
                item_2.setTextAlignment(Qt.AlignCenter)
                item_3 = QStandardItem(watchers)
                item_3.setTextAlignment(Qt.AlignCenter)
                item_4 = QStandardItem(on_loads)
                item_4.setTextAlignment(Qt.AlignCenter)
                item_5 = QStandardItem(bookmarks)
                item_5.setTextAlignment(Qt.AlignCenter)
                #item_6 = QStandardItem(user_script_item)
                #item_6.setTextAlignment(Qt.AlignCenter)

                self._recent_list_model.insertRow(
                    self._recent_list_model.rowCount(), [
                        recent_session_file_item, item_1, item_2, item_3,
                        item_4, item_5
                    ])
            else:
                invalid_session_files.append(recent_session_file)
        for invalid in invalid_session_files:
            session_history.pop(session_history.index(invalid))
        self._prefs.put(prefs.RECENT_SESSIONS, session_history)

        h_box.addLayout(wrapper, stretch=False)
        main_wrap.addLayout(h_box)
        self.setLayout(main_wrap)

    def _on_dwarf_isupdate(self):
        self.update_bar.setVisible(True)
        self.setFixedHeight(self.height() + self.update_bar.height())
        self.onIsNewerVersion.emit()

    def _update_dwarf(self):
        self._update_thread = DwarfUpdateThread(self)
        self._update_thread.on_finished.connect(self._update_finished)
        if not self._update_thread.isRunning():
            self._update_thread.start()

    def _update_finished(self):
        self.onUpdateComplete.emit()

    def _on_android_button(self):
        self.onSessionSelected.emit('Android')
        self.close()

    def _on_local_button(self):
        self.onSessionSelected.emit('Local')
        self.close()

    def _on_ios_button(self):
        self.onSessionSelected.emit('Ios')
        self.close()

    def _on_remote_button(self):
        self.onSessionSelected.emit('Remote')
        self.close()

    def _pick_random_word(self, arr):
        return self._sub_titles[arr][random.randint(
            0,
            len(self._sub_titles[arr]) - 1)]

    def _on_recent_sessions_context_menu(self, pos):
        index = self.list_view.indexAt(pos).row()
        glbl_pt = self.list_view.mapToGlobal(pos)
        context_menu = QMenu(self)
        if index != -1:
            context_menu.addAction(
                'Delete recent session', lambda: self._remove_recent_sessions(
                    self._recent_list_model.item(index, 0).text()))

            context_menu.exec_(glbl_pt)

    def _remove_recent_session(self, session_file):
        if os.path.exists(session_file):
            os.remove(session_file)
            session_history = self._prefs.get(
                prefs.RECENT_SESSIONS, default=[])
            if session_file in session_history:
                session_history.pop(session_history.index(session_file))
                self._prefs.put(prefs.RECENT_SESSIONS, session_history)

    def _on_recent_session_double_click(self, model_index):
        row = self._recent_list_model.itemFromIndex(model_index).row()
        recent_session_file = self._recent_list_model.item(row, 0)
        recent_session_data = recent_session_file.data(Qt.UserRole + 2)
        self.onSessionRestore.emit(recent_session_data)

    def showEvent(self, QShowEvent):
        """ override to change font size when subtitle is cutted
        """
        if len(self._sub_title.text()) * self._char_width > (
                self._sub_title.width() - 155):
            self._sub_title.setFont(QFont('OpenSans', 14, QFont.Bold))
        return super().showEvent(QShowEvent)
