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
from ui.widget_item_not_editable import NotEditableListWidgetItem


class AndroidAppWidget(NotEditableListWidgetItem):
    def __init__(self, application):
        super().__init__(application.name)

        self.appname = application.name
        self.package_name = application.identifier

    def get_package_name(self):
        return self.package_name


class AndroidPackageWidget(NotEditableListWidgetItem):
    def __init__(self, label, package_name, pid, apk_path=''):
        super().__init__(label)

        self.appname = label
        self.package_name = package_name
        self.pid = pid
        self.apk_path = apk_path

    def get_apk_path(self):
        return self.apk_path

    def get_package_name(self):
        return self.package_name

    def get_pid(self):
        return self.pid
