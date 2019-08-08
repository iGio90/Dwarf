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
import os


def main():
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
    path = input("project path (%s): " % current_path)
    if len(path) == 0:
        path = current_path
    if not os.path.exists(path):
        print("the specified path does not exists")
        exit(1)

    current_project_name = current_path.split(os.sep)[-1]
    project_name = input("project name (%s): " % current_project_name)
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

    session_type = input('what\'s the session type? L:local A:android I:iOS R:remote (L): ')
    if session_type:
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
            target = input('target binary and arguments: ')
            if not os.path.exists(target.split(' ')[0]):
                target = ''
        else:
            target = input('target package: ')

    dwarf_launcher = 'dwarf -sp -s agent.js -t %s %s' % (session_type, target)
    injector_exe = 'dwarf'
    if os.name == 'nt':
        injector_exe += '.bat'
    injector = os.path.join(path, injector_exe)
    with open(injector, 'w') as f:
        f.write(dwarf_launcher)

    os.system("cd %s && npm install" % path)

    print('')
    print("project create at %s. edit src/agent.ts" % path)
    print("run `npm run watch` in the project path to automatically build the agent while you code it")
    print('use %s in current path to start Dwarf' % injector_exe)
    print('')
    exit(0)
