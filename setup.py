from setuptools import setup, find_packages

from dwarf.dwarf import __version__

setup(

    # Package info
    name = 'dwarf',
    version = __version__,
    packages = find_packages(),
    python_requires='>=3',
    package_data={
        '': ['assets/*'],
        '': ['assets/icons/*'],
        '': ['lib/core.js']
    },
    zip_safe=False,
    include_package_data=True,
    # Dependencies
    install_requires = [
        'capstone>=4.0.1',
        'requests>=2.18.4',
        'frida>=12.6.11',
        'PyQt5>=5.11.3',
        'pyperclip>=1.7.0'
    ],
    # Script info
    entry_points = {
        'console_scripts': [
            'dwarf = dwarf.dwarf:main'
        ]
    }
)