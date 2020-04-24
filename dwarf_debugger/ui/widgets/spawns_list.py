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
import frida

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QHeaderView, QVBoxLayout, QPushButton, QCheckBox

from dwarf_debugger.ui.widgets.list_view import DwarfListView


class SpawnsThread(QThread):
    """ Updates the SpawnsList
        signals:
            clear_proc()
            add_spawn()
            is_error(str) - shows str in statusbar
        device must set before run
    """
    add_spawn = pyqtSignal(list)
    is_error = pyqtSignal(str)
    is_finished = pyqtSignal()

    def __init__(self, parent=None, device=None):
        super().__init__(parent)
        if device is None:
            return
        if isinstance(device, frida.core.Device):
            self.device = device

    def run(self):
        """ thread func
        """
        if self.device is not None:
            try:
                apps = self.device.enumerate_applications()
                for app in sorted(apps, key=lambda x: x.name):
                    self.add_spawn.emit([app.name, app.identifier])
            except frida.ServerNotRunningError:
                self.is_error.emit('unable to connect to remote frida server: not started')
            except frida.TransportError:
                self.is_error.emit('unable to connect to remote frida server: closed')
            except frida.TimedOutError:
                self.is_error.emit('unable to connect to remote frida server: timedout')
            except Exception as e:  # pylint: disable=broad-except
                self.is_error.emit('something was wrong...\n' + str(e))

        self.is_finished.emit()


class SpawnsList(QWidget):
    """ ProcessListWidget wich shows running Processes on Device
        Includes a Refresh Button to manually start refreshthread

        args:
            device needed

        Signals:
            onProcessSelected([pid, name]) - pid(int) name(str)
            onRefreshError(str)
    """

    onProcessSelected = pyqtSignal(list, name='onProcessSelected')
    onRefreshError = pyqtSignal(str, name='onRefreshError')

    def __init__(self, device, parent=None):
        super(SpawnsList, self).__init__(parent=parent)

        self.break_at_start = False

        self._device = device

        self.spawn_list = DwarfListView()

        model = QStandardItemModel(0, 2, parent)
        model.setHeaderData(0, Qt.Horizontal, "Name")
        model.setHeaderData(1, Qt.Horizontal, "Package")

        self.spawn_list.doubleClicked.connect(self._on_item_clicked)

        v_box = QVBoxLayout()
        v_box.setContentsMargins(0, 0, 0, 0)
        v_box.addWidget(self.spawn_list)

        break_spawn_start = QCheckBox('Break at spawn')
        break_spawn_start.stateChanged.connect(self._on_toggle_break_spawn)
        v_box.addWidget(break_spawn_start)

        self.refresh_button = QPushButton('Refresh')
        self.refresh_button.clicked.connect(self._on_refresh_procs)
        self.refresh_button.setEnabled(False)
        v_box.addWidget(self.refresh_button)
        self.setLayout(v_box)

        self.spawn_list.setModel(model)
        self.spawn_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)

        self.spaw_update_thread = SpawnsThread(self, self._device)
        self.spaw_update_thread.add_spawn.connect(self._on_add_proc)
        self.spaw_update_thread.is_error.connect(self._on_error)
        self.spaw_update_thread.is_finished.connect(self._on_refresh_finished)
        self.spaw_update_thread.device = self._device
        self.spaw_update_thread.start()

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def device(self):
        """ Sets Device needs frida.core.device
        """
        return self._device

    @device.setter
    def device(self, value):
        self.set_device(value)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def clear(self):
        """ Clears the List
        """
        self.spawn_list.clear()

    def set_device(self, device):
        """ Set frida Device
        """
        if isinstance(device, frida.core.Device):
            self._device = device
            self.spaw_update_thread.device = device
            self._on_refresh_procs()

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_item_clicked(self, model_index):
        model = self.spawn_list.model()

        index = model.itemFromIndex(model_index).row()

        if index != -1:
            sel_pid = self.spawn_list.get_item_text(index, 0)
            if model_index.column() == 0:
                sel_name = model.data(model_index, Qt.UserRole + 2)
            else:
                sel_name = self.spawn_list.get_item_text(index, 1)

            self.onProcessSelected.emit([sel_pid, sel_name])

    def _on_add_proc(self, item):
        model = self.spawn_list.model()
        name = QStandardItem()
        name.setText(item[0])
        name.setData(item[1], Qt.UserRole + 2)
        package = QStandardItem()
        package.setText(item[1])
        model.appendRow([name, package])

    def _on_error(self, error_str):
        self.onRefreshError.emit(error_str)

    def _on_refresh_procs(self):
        if not self._device:
            return

        if self.spaw_update_thread.isRunning():
            self.spaw_update_thread.terminate()

        if not self.spaw_update_thread.isRunning():
            self.clear()
            self.refresh_button.setEnabled(False)
            self.spaw_update_thread.device = self._device
            self.spaw_update_thread.start()

    def _on_refresh_finished(self):
        self.spawn_list.resizeColumnToContents(0)
        self.refresh_button.setEnabled(True)

    def _on_toggle_break_spawn(self, state):
        self.break_at_start = state == Qt.Checked
