import platform
import sys

from cx_Freeze import setup, Executable


def getTargetName():
    myOS = platform.system()
    if myOS == 'Linux':
        return "dwarf"
    elif myOS == 'Windows':
        return "dwarf.exe"
    else:
        return "dwarf.dmg"


build_exe_options = {
    "packages": ["os", "lib", "ui", "requests", "capstone", "queue", "frida", "pyperclip"],
    "include_msvcr": True,
    'include_files': ['assets']
}

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(name="Dwarf",
      version="1.0",
      description='Full featured multi arch/os debugger built on top of PyQt5 and frida',
      options={"build_exe": build_exe_options},
      executables=[Executable("dwarf.py", base=base, targetName=getTargetName())])
