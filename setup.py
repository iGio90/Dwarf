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
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""
from setuptools import setup, find_packages

from dwarf.dwarf import DWARF_VERSION

setup(

    # Package info
    name='dwarf',
    version=DWARF_VERSION,
    packages=find_packages(),
    python_requires='>=3',
    package_data={'': ['assets/*', 'assets/icons/*', 'lib/core.js']},
    zip_safe=False,
    include_package_data=True,
    # Dependencies
    install_requires=[
        'capstone==4.0.1', 'requests==2.22.0', 'frida==12.6.11',
        'PyQt5==5.11.3', 'pyperclip==1.7.0'
    ],
    # Script info
    entry_points={'console_scripts': ['dwarf = dwarf.dwarf:main']})
