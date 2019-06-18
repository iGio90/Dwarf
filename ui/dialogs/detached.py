from PyQt5.QtWidgets import QVBoxLayout, QLabel, QHBoxLayout, QPushButton, QDialog

from ui.dialogs.dwarf_dialog import DwarfDialog


class QDialogDetached(DwarfDialog):
    def __init__(self, dwarf, process, reason, crash_log, parent=None):
        super(QDialogDetached, self).__init__(parent)
        self.dwarf = dwarf

        layout = QVBoxLayout(self)

        self.setMinimumWidth(500)

        layout.addWidget(QLabel('%d detached with reason: %s\n' % (process.pid, reason)))

        self._restart = False

        buttons = QHBoxLayout()
        do_noting = QPushButton('ok')
        do_noting.clicked.connect(self.close)
        buttons.addWidget(do_noting)
        if dwarf._spawned:
            restart = QPushButton('restart')
            restart.clicked.connect(self.restart)
            buttons.addWidget(restart)

        layout.addLayout(buttons)

    def restart(self):
        self._restart = True
        self.accept()

    @staticmethod
    def show_dialog(dwarf, process, reason, crash_log):
        dialog = QDialogDetached(dwarf, process, reason, crash_log)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            if dialog._restart:
                return 0
        return -1
