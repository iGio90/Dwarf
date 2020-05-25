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
import os


def main():
    from dwarf_debugger.color import Color
    from io import open
    import json

    agent_template = """"""

    package_template = {
        "name": "dwarf-agent-template",
        "version": "1.0.0",
        "description": "Dwarf agent template ready to be filled",
        "main": "src/agent.ts",
        "license": "LICENSE.md",
        "scripts": {
            "prepare": "npm run build",
            "build": "frida-compile src/agent.ts -o agent.js",
            "watch": "frida-compile src/agent.ts -o agent.js -w"
        },
        "devDependencies": {
            "@types/dwarf-typings": "git://github.com/iGio90/DwarfTypings.git",
            "@types/frida-gum": "^13.0.0",
            "@types/node": "^12.0.4",
            "frida-compile": "^9.0.2"
        }
    }

    tsconfig_template = {
        "compilerOptions": {
            "target": "esnext",
            "lib": ["esnext"],
            "allowJs": True,
            "noEmit": True,
            "strict": False,
            "esModuleInterop": True
        },
        "include": [
            "src/**/*"
        ]
    }

    current_path = os.getcwd()
    path = input("%s (%s):\n" % (Color.colorify('project path', 'red bold'), Color.colorify(current_path, 'bold')))
    if len(path) == 0:
        path = current_path
    if not os.path.exists(path):
        print("the specified path does not exists")
        exit(1)

    current_project_name = current_path.split(os.sep)[-1]
    project_name = input("%s (%s):\n" % (
        Color.colorify('project name', 'red bold'), Color.colorify(current_project_name, 'bold')))
    if len(project_name) == 0:
        project_name = current_project_name
    package_template["name"] = project_name

    with open(os.path.join(path, "package.json"), 'w', encoding='utf-8') as f:
        f.write(json.dumps(package_template, indent=4))
    with open(os.path.join(path, "tsconfig.json"), 'w', encoding='utf-8') as f:
        f.write(json.dumps(tsconfig_template, indent=4))

    agent_path = os.path.join(path, 'src')
    if not os.path.exists(agent_path):
        os.mkdir(agent_path)
    with open(os.path.join(agent_path, "agent.ts"), 'w', encoding='utf-8') as f:
        f.write(agent_template)

    print('%s (%s)' % (Color.colorify('Session type', 'red bold'), Color.colorify('local', 'bold')))
    print('[%s] %s (%s)' % (
        Color.colorify('*', 'green bold'), Color.colorify('L', 'red bold'), Color.colorify('local', 'bold')))
    print('[%s] %s (%s)' % (
        Color.colorify('*', 'green bold'), Color.colorify('A', 'red bold'), Color.colorify('android', 'bold')))
    print('[%s] %s (%s)' % (
        Color.colorify('*', 'green bold'), Color.colorify('I', 'red bold'), Color.colorify('iOS', 'bold')))
    print('[%s] %s (%s)' % (
        Color.colorify('*', 'green bold'), Color.colorify('R', 'red bold'), Color.colorify('remote', 'bold')))
    print('')
    print('append %s to use dwarf-injector (%s | %s)' % (
        Color.colorify('i', 'white bold'),
        Color.colorify('ai', 'green bold'),
        Color.colorify('android inject', 'bold')))
    session_type = input('')

    inject = False
    if session_type:
        if len(session_type) > 1:
            inject = session_type[1] == 'i'
            session_type = session_type[0]
        session_type = session_type.lower()
        if session_type == 'a':
            session_type = 'android'
        elif session_type == 'i':
            session_type = 'ios'
        elif session_type == 'r':
            session_type = 'remote'
        else:
            session_type = 'local'
    else:
        session_type = 'local'

    target = ''
    while len(target.replace(' ', '')) == 0:
        if session_type == 'local':
            target = input('%s (%s)\n' % (
                Color.colorify('target binary and arguments', 'red bold'),
                Color.colorify('/bin/cat /etc/hosts', 'bold')))
            if not os.path.exists(target.split(' ')[0]):
                target = ''
        else:
            target = input('%s (%s)\n' % (
                Color.colorify('target package', 'red bold'), Color.colorify('com.whatsapp', 'bold')))

    binary = 'dwarf'
    if inject:
        binary += '-injector'
    dwarf_launcher = 'npm run build'
    injector_exe = 'dwarf'
    if os.name == 'nt':
        dwarf_launcher += ' && ^'
        injector_exe = 'launch_dwarf.bat'
    dwarf_launcher += '\n%s -sp -s agent.js -t %s %s' % (binary, session_type, target)
    injector = os.path.join(path, injector_exe)
    with open(injector, 'w') as f:
        f.write(dwarf_launcher)

    os.system("cd \"%s\" && npm install" % path)
    if os.name != 'nt':
        os.system("cd \"%s\" && chmod a+x dwarf" % path)

    print('')
    print("project create at %s. edit src/agent.ts" % path)
    print('use %s in current path to start Dwarf' % injector_exe)
    print('')
    exit(0)
