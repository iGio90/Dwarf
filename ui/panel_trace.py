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
import time
from threading import Thread

from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class TraceEvent(object):
    def __init__(self, type, location, target, depth):
        self.type = type
        self.location = location
        self.target = target
        self.depth = int(depth)


class TracePanel(TableBaseWidget):
    MAX_HIT_COUNT = 1000

    def __init__(self, app):
        super().__init__(app, 0, 0)

        self._worker = None
        self._run = False
        self._hit_count = 0
        self.event_queue = []

    def add_trace_event(self, event):
        row = self.rowCount()
        self.insertRow(row)

        q = MemoryAddressWidget(event.location)
        q.setText('%s%s' % (' ' * (event.depth * 4), event.location))
        self.setItem(row, 0, q)
        q = MemoryAddressWidget(event.target)
        self.setItem(row, 1, q)

    def start(self):
        if self._worker is None:
            self._run = True
            self.setColumnCount(2)
            self.setRowCount(0)
            self.setHorizontalHeaderLabels(['location', 'target'])
            self.horizontalHeader().setStretchLastSection(True)
            self.event_queue.clear()
            self._worker = Thread(target=self._work)
            self._worker.start()

    def stop(self):
        self._run = False

    def _work(self):
        self._hit_count = 0
        while self._run:
            if len(self.event_queue) > 0:
                event = self.event_queue.pop(0)
                self.add_trace_event(event)
                self._hit_count += 1
                if self._hit_count >= TracePanel.MAX_HIT_COUNT:
                    self.app.get_dwarf().native_tracer_stop()
                    break
            else:
                time.sleep(0.5)
        self._hit_count = 0
        self.event_queue.clear()
        self._worker = None
