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
import os

import urllib.request


def tool_exist(tool):
    if not os.path.exists('tools'):
        os.mkdir('tools')
        return False
    return os.path.exists('tools/%s' % tool)


def get_tool(url, path):
    if not os.path.exists('tools'):
        os.mkdir('tools')

    urllib.request.urlretrieve(url, 'tools/%s' % path)
