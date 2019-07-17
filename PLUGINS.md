### Create a plugin

this will give you a basic how-to instantantiate your plugin, which will receive the qt main application as object.
this object allows you to alter, create ui elements and to access dwarf core (for speak with frida).

Your best environment to create and debug a plugin will be an IDE with Dwarf project opened (so you have api references and completition). You will then create the plugins folder in dwarf path (if not existing), and creare a directory with the plugin name

> dwarf_path/plugins/my_plugin/

create a file called plugin.py (this is mandatory)

> dwarf_path/plugins/my_plugin/plugin.py

then you have to instantiate the main class for your plugin, which must be named "Plugin".

you than have to define the ``__get_plugin_info__`` method and declare 2 special methods
```python
class Plugin:
    def __get_plugin_info__(self):
        return {
            'name': 'my plugin',
            'description': 'my plugin description',
            'version': '1.0.0',
            'author': 'my name',
            'homepage': 'https://github.com/repo',
            'license': 'https://www.gnu.org/licenses/gpl-3.0',
        }

    def __get_top_menu_actions__(self):
        pass

    def __get_agent__(self):
        pass
     
    def __init__(self, app):
        self.app = app
```

that's it.

for reference, I'm posting r2dwarf code as an example, you can [checkout the full impl here](https://github.com/iGio90/R2Dwarf)

```python
class Plugin:
    def __get_plugin_info__(self):
        return {
            'name': 'r2dwarf',
            'description': 'r2frida in Dwarf',
            'version': '1.0.0',
            'author': 'iGio90',
            'homepage': 'https://github.com/iGio90/Dwarf',
            'license': 'https://www.gnu.org/licenses/gpl-3.0',
        }

    def __get_top_menu_actions__(self):
        if len(self.menu_items) > 0:
            return self.menu_items

        options = QAction('Options')
        options.triggered.connect(lambda: OptionsDialog.show_dialog(self._prefs))

        self.menu_items.append(options)
        return self.menu_items

    def __get_agent__(self):
        self.app.dwarf.onReceiveCmd.connect(self._on_receive_cmd)

        # we create the first pipe here to be safe that the r2 agent is loaded before the first breakpoint
        # i.e if we start dwarf targetting a package from args and a script breaking at first open
        # dwarf will hang because r2frida try to load it's agent and frida turn to use some api uth which are
        # not usable before the breakpoint quit
        # __get_agent__ is request just after our agent load and it solved all the things
        # still not the best solution as if the pipe got broken for some reason and we re-attempt to create it
        # while we are in a bkp we will face the same shit
        self._create_pipe()

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent.js'), 'r') as f:
            return f.read()

    def __init__(self, app):
        self.app = app

        # block the creation of pipe on fatal errors
        self.pipe_locker = False

        self._prefs = Prefs()
        self.pipe = None
        self.current_seek = ''
        self.with_r2dec = False
        self._working = False

        self.r2_widget = None

        self.menu_items = []

        self.app.session_manager.sessionCreated.connect(self._on_session_created)
        self.app.session_manager.sessionStopped.connect(self._on_session_stopped)
        self.app.onUIElementCreated.connect(self._on_ui_element_created)
```