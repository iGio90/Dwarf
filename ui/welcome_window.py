
import json

from PyQt5.QtCore import Qt, QSize, QRect, pyqtSignal, QThread, QMargins
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtWidgets import QWidget, QListWidget, QListWidgetItem, QDialog, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QListView, QSpacerItem, QSizePolicy, QStyle, qApp

from lib import utils
from lib.git import Git


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
                self.on_status_text.emit('error: git not available on your system')
                return
        _git = Git()
        data = _git.get_dwarf_commits()
        if data is None:
            self.on_status_text.emit('Failed to fetch commit list. Try later.')
            return

        most_recent_remote_commit = ''
        most_recent_local_commit = utils.do_shell_command('git log -1 master --pretty=format:%H')
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

            s = ('{0} - {1} ({2})'.format(date[1][:-1], commit['message'], commit['author']['name']))
            self.on_add_commit.emit(s, False)

        if most_recent_remote_commit != most_recent_local_commit:
            self.on_finished.emit('There is an newer Version available... You can use the UpdateButton in Menu')
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
                self.on_status_text.emit('error while updating: git not available on your system')
                self.on_finished.emit('error while updating: git not available on your system')
                return

        utils.do_shell_command('git fetch -q https://github.com/iGio90/Dwarf.git')
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
        self.setStyleSheet('background-color: crimson; color: white; font-weight: bold; margin: 0; padding: 10px;')
        self.setup()

    def setup(self):
        """ Setup ui
        """
        h_box = QHBoxLayout()
        h_box.setContentsMargins(0, 0, 0, 0)
        update_label = QLabel('A newer Version of Dwarf is available. Checkout <a style="color:white;" '
                              'href="https://github.com/iGio90/Dwarf">Dwarf on GitHub</a> for more informations')
        update_label.setOpenExternalLinks(True)
        update_label.setTextFormat(Qt.RichText)
        update_label.setFixedHeight(35)
        update_label.setTextInteractionFlags(Qt.TextBrowserInteraction)

        update_button = QPushButton('Update now!', update_label)
        update_button.setStyleSheet('padding: 0; border-color: white;')
        update_button.setGeometry(update_label.width() + 50, 5, 100, 25)
        update_button.clicked.connect(self.update_now_clicked)
        h_box.addWidget(update_label)
        self.setLayout(h_box)

    def update_now_clicked(self):
        """ Update Button clicked
        """
        self.onUpdateNowClicked.emit()


class WelcomeDialog(QDialog):

    onSessionSelected = pyqtSignal(str, name='onSessionSelected')
    onUpdateComplete = pyqtSignal(name='onUpdateComplete')
    onIsNewerVersion = pyqtSignal(name='onIsNewerVersion')

    def __init__(self, parent=None):
        super(WelcomeDialog, self).__init__(parent=parent)

        self._prefs = parent.prefs

        self.recent_list = QListWidget(self)
        # setup size and remove/disable titlebuttons
        self.setFixedSize(800, 400)
        self.setSizeGripEnabled(False)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)
        self.setModal(True)

        # setup ui elements
        self.setup_ui()

        self.update_commits_thread = DwarfCommitsThread(parent)
        self.update_commits_thread.on_update_available.connect(self._on_dwarf_isupdate)
        self.update_commits_thread.start()
        # center
        self.setGeometry(QStyle.alignedRect(Qt.LeftToRight, Qt.AlignCenter, self.size(), qApp.desktop().availableGeometry()))

        saved_sessions = self._prefs.get('dwarf_mru', '{}')
        saved_sessions = json.loads(saved_sessions)
        for saved in saved_sessions:
            self.recent_list.addItem(QListWidgetItem(saved['path']))

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
        #wrapper.setGeometry(QRect(0, 0, 400, 200))
        head = QHBoxLayout()
        # dwarf icon
        icon = QLabel()
        icon.setContentsMargins(100, 0, 20, 0)
        icon.setPixmap(QPixmap(utils.resource_path('assets/dwarf.png')))
        head.addWidget(icon)

        # main title
        title = QLabel('Dwarf')
        title.setFont(QFont('Anton', 85, QFont.Bold))
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        head.addWidget(title)

        wrapper.addLayout(head)

        recent = QLabel('Last saved Sessions')
        font = recent.font()
        font.setBold(True)
        font.setPointSize(10)
        recent.setFont(font)
        wrapper.addWidget(recent)
        wrapper.addWidget(self.recent_list)
        h_box.addLayout(wrapper, stretch=False)
        buttonSpacer = QSpacerItem(15, 100, QSizePolicy.Fixed, QSizePolicy.Minimum)
        h_box.addItem(buttonSpacer)
        wrapper = QVBoxLayout()

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/android.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Android Session')
        btn.clicked.connect(self._on_android_button)

        wrapper.addWidget(btn)
        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/apple.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New iOS Session')
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/local.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Local Session')
        btn.clicked.connect(self._on_local_button)
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/remote.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Remote Session')
        wrapper.addWidget(btn)

        h_box.addLayout(wrapper, stretch=False)
        main_wrap.addLayout(h_box)
        self.setLayout(main_wrap)

    def _on_dwarf_isupdate(self):
        self.update_bar.setVisible(True)
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
