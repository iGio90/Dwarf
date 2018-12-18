from PyQt5.QtWidgets import QAction


def get_qmenu_separator():
    separator = QAction("--------------------")
    separator.setEnabled(False)
    return separator
