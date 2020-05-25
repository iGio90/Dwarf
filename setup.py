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
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""
from setuptools import setup, find_packages

from dwarf_debugger.version import DWARF_VERSION

setup(

    # Package info
    name='dwarf_debugger',
    version=DWARF_VERSION,
    author="Giovanni Rocca (iGio90)",
    author_email="giovanni.rocca.90@gmail.com",
    license='GPLv3+',
    description=
    "Full featured multi arch/os debugger built on top of PyQt5 and frida",
    long_description=
    "A debugger for reverse engineers, crackers and security analyst. Or you can call it damn, why are raspberries so fluffy or yet, duck warriors are rich as fuck. Whatever you like! Built on top of pyqt5, frida and some terrible code.",
    long_description_content_type="text/markdown",
    url="https://github.com/iGio90/Dwarf",
    packages=find_packages(),
    python_requires='>=3',
    package_data={'': ['assets/*', 'assets/icons/*', 'lib/core.js']},
    zip_safe=False,
    include_package_data=True,
    # Dependencies
    install_requires=[
        'capstone>=4.0.1', 'requests>=2.22.0', 'frida>=12.8.0',
        'PyQt5>=5.11.3', 'pyperclip>=1.7.0'
    ],
    # Script info
    entry_points={'console_scripts':
        [
            'dwarf = dwarf_debugger.dwarf:main',
            'dwarf-creator = dwarf_debugger.creator:main',
            'dwarf-injector = dwarf_debugger.injector:main',
            'dwarf-trace = dwarf_debugger.trace:main'
        ]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Science/Research",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Security"
    ]
)
