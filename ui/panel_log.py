from PyQt5.QtWidgets import QListWidget, QListWidgetItem

from ui.widget_item_not_editable import NotEditableListWidgetItem


class LogPanel(QListWidget):
    def __init__(self):
        super().__init__()

    def add_to_main_content_content(self, what, clear=False, scroll=False):
        if clear:
            self.log_panel.clear()

        if isinstance(what, QListWidgetItem):
            self.log_panel.addItem(what)
        else:
            item = NotEditableListWidgetItem(what)
            self.log_panel.addItem(item)

        if scroll:
            self.log_panel.scrollToBottom()
